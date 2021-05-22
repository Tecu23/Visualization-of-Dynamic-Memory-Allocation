install3: # installing python 3 depencies
	pip3 install unicorn
	pip3 install arcade
	pip3 install numpy

install: # installing python 2 depencies
	pip install unicorn
	pip install arcade
	pip install numpy

run3: # running the application with python 3
	python3 main.py

run: # running the application with python 2
	python main.py

clean: # removing the unecessairy files
	rm -rf __pycache__