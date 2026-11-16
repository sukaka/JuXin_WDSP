package com.jiuzhang.wdsp.agent;

import java.lang.instrument.Instrumentation;
import java.util.LinkedHashSet;
import java.util.Set;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.dynamic.loading.ClassInjector;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.pool.TypePool;

public final class WdspAgent {
    private static final Set<String> HELPER_CLASSES = new LinkedHashSet<>(Set.of(
        "com.jiuzhang.wdsp.agent.CaptureConfig",
        "com.jiuzhang.wdsp.agent.CaptureReporter",
        "com.jiuzhang.wdsp.agent.TraceSupport",
        "com.jiuzhang.wdsp.agent.Json",
        "com.jiuzhang.wdsp.agent.UnixSocketClient",
        "com.jiuzhang.wdsp.agent.BoundedOutputStream",
        "com.jiuzhang.wdsp.agent.BoundedInputStream",
        "com.jiuzhang.wdsp.agent.BoundedServletOutputStream",
        "com.jiuzhang.wdsp.agent.BoundedHttpServletResponseWrapper",
        "com.jiuzhang.wdsp.agent.CapturingRequestCallback",
        "com.jiuzhang.wdsp.agent.CapturingClientHttpRequest",
        "com.jiuzhang.wdsp.agent.CapturingResponseExtractor",
        "com.jiuzhang.wdsp.agent.DelegatingClientHttpResponse",
        "com.jiuzhang.wdsp.agent.SpringMvcAdvice",
        "com.jiuzhang.wdsp.agent.RestTemplateAdvice"
    ));

    private WdspAgent() {}

    public static void premain(String arguments, Instrumentation instrumentation) {
        install(instrumentation);
    }

    public static void agentmain(String arguments, Instrumentation instrumentation) {
        install(instrumentation);
    }

    private static void install(Instrumentation instrumentation) {
        System.err.println("WDSP API agent installing Spring MVC and RestTemplate instrumentation");
        new AgentBuilder.Default()
            .with(new AgentBuilder.Listener.Adapter() {
                @Override
                public void onError(String typeName, ClassLoader classLoader, net.bytebuddy.utility.JavaModule module, boolean loaded, Throwable cause) {
                    CaptureReporter.noteFailure("instrumentation " + typeName, cause);
                }
            })
            .ignore(ElementMatchers.nameStartsWith("com.jiuzhang.wdsp.agent.")
                .or(ElementMatchers.nameStartsWith("net.bytebuddy.")))
            .type(ElementMatchers.hasSuperType(ElementMatchers.named("org.springframework.web.servlet.DispatcherServlet")))
            .transform((builder, type, classLoader, module, protectionDomain) -> {
                injectHelpers(classLoader);
                return builder.visit(advice("com.jiuzhang.wdsp.agent.SpringMvcAdvice", classLoader).on(ElementMatchers.named("doService")));
            })
            .type(ElementMatchers.hasSuperType(ElementMatchers.named("org.springframework.web.client.RestTemplate")))
            .transform((builder, type, classLoader, module, protectionDomain) -> {
                injectHelpers(classLoader);
                return builder.visit(advice("com.jiuzhang.wdsp.agent.RestTemplateAdvice", classLoader).on(ElementMatchers.named("doExecute").and(ElementMatchers.takesArguments(5))));
            })
            .installOn(instrumentation);
        System.err.println("WDSP API agent installed");
    }

    private static void injectHelpers(ClassLoader applicationLoader) {
        if (applicationLoader == null) return;
        ClassFileLocator locator = ClassFileLocator.ForClassLoader.of(WdspAgent.class.getClassLoader());
        new ClassInjector.UsingReflection(applicationLoader).injectRaw(HELPER_CLASSES, locator);
    }

    private static Advice advice(String className, ClassLoader applicationLoader) {
        ClassFileLocator agentLocator = ClassFileLocator.ForClassLoader.of(WdspAgent.class.getClassLoader());
        ClassFileLocator applicationLocator = ClassFileLocator.ForClassLoader.of(applicationLoader);
        ClassFileLocator locator = new ClassFileLocator.Compound(agentLocator, applicationLocator);
        TypeDescription description = TypePool.Default.of(locator).describe(className).resolve();
        return Advice.to(description, locator);
    }
}
