ENVPYTHON=devel/bin/python
ENVPIP=devel/bin/pip

default: devel install

devel:
	python -m venv devel
	$(ENVPIP) install --upgrade pip setuptools wheel build ipython

.PHONY: build install clean update
build:
	$(ENVPYTHON) -m build

install:
	$(ENVPIP) install .

clean:
	rm -rf dist
	rm -rf devel
	rm -rf src/*.egg-info
