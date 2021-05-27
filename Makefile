install: # installing python 3 depencies
	pip3 install unicorn
	pip3 install arcade
	pip3 install numpy

run: # running the application with python 3
	python3 main.py

clean: # removing the unecessairy files
	rm -rf __pycache__