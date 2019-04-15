DIRS = util get getd

RM = /bin/rm -f

.SILENT:

.PHONY: bin clean

bin:
	for dir in $(DIRS); do \
		echo "Making directory $$dir"; \
		$(MAKE) -C $$dir; \
	done

clean:
	for dir in $(DIRS); do \
		echo "Cleaning directory $$dir"; \
		$(MAKE) -C $$dir clean; \
	done
