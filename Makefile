# Dummy makefile to call scons
SCONS=scons
all:
	@$(SCONS)

clean:
	@$(SCONS) -c
