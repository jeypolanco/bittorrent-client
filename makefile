tor_num=$(shell find -H . -maxdepth 1 -iname "*torrent" | wc -l)
ran_num=$(shell mawk 'BEGIN{srand();printf("%d", 65536*rand() % $(tor_num) + 1)}')
tor_file=$(shell find -H . -maxdepth 1 -iname "*torrent" | sed -n '$(ran_num)p')

# I changed this to test1.torrent because test.torrent seems to not work
run: main.py
	python main.py test1.torrent

rrun: main.py
	python main.py $(tor_file)

testtorrentparse: main.py
	python -m unittest testtorrentparser

# Version control stuff
## These are all phony targets

status: 
	git status

log:
	git --no-pager log

branch:
	git branch

