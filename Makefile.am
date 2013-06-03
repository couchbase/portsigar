ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = $(SIGAR_CPPFLAGS)
AM_LDFLAGS = $(SIGAR_LDFLAGS)
bin_PROGRAMS = sigar_port

if WINDOWS
dist_EXTRA = wmi_port.cc
sigar_port.exe:
	cmd /c winbuild.bat /MT /Fesigar_port.exe wmi_port.cc
clean:
	rm -f wmi_port.obj wmi_port.exe
else
sigar_port_SOURCES = sigar_port.c
endif

check-syntax:
	$(COMPILE) -o /dev/null -S ${CHK_SOURCES}

%.s : %.c
	$(COMPILE) -S -fverbose-asm -o $@ $<
