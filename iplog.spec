Summary: A port scan detection tool.
Name: iplog
Version: 2.2.3
Release: 1
License: GPL
Group: System Environment/Daemons
URL: http://ojnk.sourceforge.net/
Source0: http://download.sourcrforge.net/ojnk/%{name}-%{version}.tar.gz
Source1: iplog
Source2: iplog.conf
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%description
Use iplog to detect port scans.

%prep
%setup -q -n %{name}-%{version}

%build
%configure
make

%install
rm -rf %{buildroot}
%makeinstall
mkdir -p %{buildroot}/etc/rc.d/init.d
install -m 0644 %{SOURCE2} %{buildroot}/etc
install -m 0755 %{SOURCE1} %{buildroot}/etc/rc.d/init.d

%clean
rm -rf %{buildroot}

%post
/sbin/chkconfig --add iplog
/usr/sbin/groupadd -g 70 iplog > /dev/null 2>&1
/usr/sbin/useradd -c "iplog user" -d / -g 70 -M -s /bin/false -u 70 iplog > /dev/null 2>&1
exit 0

%preun
if [ "$1" = "0" ]; then
  /sbin/service iplog stop > /dev/null 2>&1
  /sbin/chkconfig --del iplog
fi

%postun
if [ "$1" -ge "1" ]; then
  /sbin/service iplog condrestart > /dev/null 2>&1
fi

%files
%defattr(-,root,root)
%attr(0755,root,root)/etc/rc.d/init.d/*
%config /etc/iplog.conf
%{_sbindir}/iplog
%{_mandir}/*/*

%changelog
* Fri Nov 24 2000 Tim Waugh <twaugh@redhat.com>
- 2.2.2

* Sun Nov 12 2000 Tim Waugh <twaugh@redhat.com>
- Packaged
