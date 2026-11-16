package com.jiuzhang.apisecurity;

import java.io.StringReader;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

public final class PayloadParser {
    private static final int MAX_QUERY_PAIRS = 256;
    private static final int MAX_VALUE_LENGTH = 4096;
    private static final int MAX_XML_NODES = 10_000;
    private static final int MAX_XML_DEPTH = 64;

    public List<Models.Parameter> parse(
        Models.RequestContext context,
        PathNormalizer.Result path
    ) {
        var parameters = new ArrayList<Models.Parameter>();
        parameters.addAll(parsePairs(
            context.requestUri().getRawQuery(), Models.ParameterLocation.QUERY
        ));
        for (var object : path.objects()) {
            parameters.add(new Models.Parameter(
                Models.ParameterLocation.PATH,
                "$path." + object.segment(),
                object.rawValue(),
                Models.ValueType.STRING
            ));
        }

        var body = new String(context.body(), StandardCharsets.UTF_8);
        if (body.isBlank()) return List.copyOf(parameters);
        try {
            switch (context.classification().protocol()) {
                case REST_JSON -> parseJson(body, parameters);
                case REST_FORM -> parameters.addAll(parsePairs(body, Models.ParameterLocation.BODY));
                case GRAPHQL -> parseGraphQL(body, parameters);
                case XML_SOAP -> parseXml(body, parameters);
                default -> {
                    return List.copyOf(parameters);
                }
            }
        } catch (IllegalArgumentException error) {
            throw new IllegalArgumentException("request payload cannot be parsed: " + error.getMessage(), error);
        }
        return List.copyOf(parameters);
    }

    private void parseJson(String body, List<Models.Parameter> parameters) {
        var root = Json.parse(body);
        if (root instanceof Map || root instanceof List) {
            addFlattened(Json.flatten(root), Models.ParameterLocation.BODY, parameters);
        } else {
            parameters.add(parameter(Models.ParameterLocation.BODY, "$", root));
        }
    }

    private void parseGraphQL(String body, List<Models.Parameter> parameters) {
        var root = Json.parseObject(body);
        addFlattened(Json.flatten(root), Models.ParameterLocation.BODY, parameters);
    }

    private void parseXml(String body, List<Models.Parameter> parameters) {
        try {
            var factory = secureXmlFactory();
            factory.setNamespaceAware(true);
            var document = factory.newDocumentBuilder().parse(
                new InputSource(new StringReader(body))
            );
            var counter = new int[]{0};
            visitXml(document.getDocumentElement(), "", parameters, counter, 0);
        } catch (ParserConfigurationException error) {
            throw new IllegalArgumentException("secure XML parser configuration failed", error);
        } catch (org.xml.sax.SAXException | java.io.IOException error) {
            throw new IllegalArgumentException("invalid XML request", error);
        }
    }

    private DocumentBuilderFactory secureXmlFactory() throws ParserConfigurationException {
        var factory = DocumentBuilderFactory.newDefaultInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        return factory;
    }

    private void visitXml(
        Node node,
        String path,
        List<Models.Parameter> parameters,
        int[] counter,
        int depth
    ) {
        counter[0]++;
        if (counter[0] > MAX_XML_NODES || depth > MAX_XML_DEPTH) {
            throw new IllegalArgumentException("XML structure exceeds parser limits");
        }
        var name = node.getLocalName() == null ? node.getNodeName() : node.getLocalName();
        var current = path.isEmpty() ? name : path + "." + name;
        var children = node.getChildNodes();
        var hasElementChild = false;
        for (int index = 0; index < children.getLength(); index++) {
            var child = children.item(index);
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                hasElementChild = true;
                visitXml(child, current, parameters, counter, depth + 1);
            }
        }
        if (!hasElementChild) {
            var value = node.getTextContent();
            if (value != null && value.length() > MAX_VALUE_LENGTH) {
                throw new IllegalArgumentException("XML value is too long");
            }
            parameters.add(parameter(Models.ParameterLocation.BODY, current, value));
        }
    }

    private List<Models.Parameter> parsePairs(String source, Models.ParameterLocation location) {
        var parameters = new ArrayList<Models.Parameter>();
        if (source == null || source.isEmpty()) return parameters;
        var pairs = source.split("&", -1);
        if (pairs.length > MAX_QUERY_PAIRS) {
            throw new IllegalArgumentException("too many request parameters");
        }
        for (String pair : pairs) {
            var parts = pair.split("=", 2);
            var name = decode(parts[0]);
            var value = parts.length == 1 ? "" : decode(parts[1]);
            if (name.isBlank() || name.length() > 256 || value.length() > MAX_VALUE_LENGTH) {
                throw new IllegalArgumentException("invalid request parameter size");
            }
            parameters.add(parameter(location, name, value));
        }
        return parameters;
    }

    private String decode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException error) {
            throw new IllegalArgumentException("invalid percent encoding", error);
        }
    }

    private void addFlattened(
        Map<String, Object> values,
        Models.ParameterLocation location,
        List<Models.Parameter> parameters
    ) {
        values.forEach((path, value) -> parameters.add(parameter(location, path, value)));
    }

    private Models.Parameter parameter(
        Models.ParameterLocation location,
        String path,
        Object value
    ) {
        return new Models.Parameter(location, path, value, Json.typeOf(value));
    }
}
