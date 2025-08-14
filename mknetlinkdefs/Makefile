all: ../netlinklib/defs.py ../netlinklib/classes.py

../netlinklib/defs.py: mkdefs
	./mkdefs >$@
	black -l79 $@

../netlinklib/classes.py: mknetlinkdefs.py
	python3 mknetlinkdefs.py $@

mkdefs: mkdefs.c

mkdefs.c: mknetlinkdefs.py
	python3 mknetlinkdefs.py ../netlinklib/classes.py

clean:
	rm -f mkdefs.c mkdefs
