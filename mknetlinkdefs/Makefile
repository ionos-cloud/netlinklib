all: ../netlinklib/defs.py ../netlinklib/classes.py

../netlinklib/defs.py: mkdefs
	./mkdefs >$@
	black -l79 $@

../netlinklib/classes.py: stage35.py sizes.py headers.py
	python3 stage35.py >$@

sizes.py: mksize
	./mksize >$@

mkdefs: mkdefs.c

mksize: mksize.c

mkdefs.c namelist.py: stage1.py headers.py
	python3 stage1.py

mksize.c: stage35.py headers.py
	python3 stage35.py -3

clean:
	rm -f mkdefs.c mkdefs namelist.py
