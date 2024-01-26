all: ../netlinklib/defs.py

../netlinklib/defs.py: mkdefs
	./mkdefs >$@

mkdefs: mkdefs.c

mkdefs.c:
	python3 mknetlinkdefs.py

clean:
	rm -f mkdefs.c mkdefs
