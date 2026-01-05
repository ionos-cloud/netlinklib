all: ../netlinklib/defs.py ../netlinklib/classes.py

../netlinklib/defs.py: mkdefs
	./mkdefs >$@
	black -l79 $@

../netlinklib/classes.py: stage3.py sizes.py headers.py
	python3 stage3.py >$@

sizes.py: mksize
	./mksize >$@

mkdefs: mkdefs.c

mksize: mksize.c

mkdefs.c mksize.c: stage1.py headers.py
	python3 stage1.py

clean:
	rm -f mkdefs.c mkdefs mksize.c mksize sizes.py
