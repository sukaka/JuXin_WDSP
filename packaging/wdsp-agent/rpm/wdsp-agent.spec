Name:           wdsp-agent
Version:        %{_wdsp_version}
Release:        1%{?dist}
Summary:        JiuZhang WDSP Distributed Traffic Agent
License:        Proprietary
URL:            https://github.com/sukaka/JuXin_WDSP

%description
Passive read-only traffic and API observation edge sensor for JiuZhang WDSP.

%install
install -d -m 0755 %{buildroot}/usr/local/bin
install -d -m 0755 %{buildroot}/usr/lib/systemd/system
install -d -m 0700 %{buildroot}/etc/wdsp-agent
install -d -m 0700 %{buildroot}/var/lib/wdsp-agent
install -m 0755 %{_wdsp_binary} %{buildroot}/usr/local/bin/wdsp-agent
install -m 0644 %{_wdsp_unit} %{buildroot}/usr/lib/systemd/system/wdsp-agent.service

%files
%attr(0755, root, root) /usr/local/bin/wdsp-agent
%attr(0644, root, root) /usr/lib/systemd/system/wdsp-agent.service
%dir %attr(0700, root, root) /etc/wdsp-agent
%dir %attr(0700, root, root) /var/lib/wdsp-agent

%post
install -d -m 0700 /etc/wdsp-agent /var/lib/wdsp-agent
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    if [ "$1" -ge 2 ] && [ -s /etc/wdsp-agent/agent.json ] && systemctl is-active --quiet wdsp-agent; then
        systemctl restart wdsp-agent >/dev/null 2>&1 || true
    fi
fi

%preun
if [ "$1" -eq 0 ]; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl stop wdsp-agent >/dev/null 2>&1 || true
        systemctl disable wdsp-agent >/dev/null 2>&1 || true
    fi
fi

%postun
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
