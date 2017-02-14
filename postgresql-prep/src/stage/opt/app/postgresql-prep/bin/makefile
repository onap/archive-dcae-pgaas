all:

NODES="uiopmno5qwpstg01.grant.example.com|uiopmno5qwpstg00.grant.example.com|uiopmno6qwpstg00.grant.example.com|uiopmno6qwpstg01.grant.example.com"

test:
	./gen-repmgr-info			-n $(NODES)
	./gen-repmgr-info -S -L			-n $(NODES)
	./gen-repmgr-info -s uiopmno6qwpstg	-n $(NODES)
	./gen-repmgr-info -l uiopmno6qwpstg01.grant.example.com -n $(NODES)
	./gen-repmgr-info -c uiopmno5qwpstg00.grant.example.com -n $(NODES)
	./gen-repmgr-info -c uiopmno5qwpstg01.grant.example.com -n $(NODES)
	./gen-repmgr-info -c uiopmno6qwpstg00.grant.example.com -n $(NODES)
	./gen-repmgr-info -c uiopmno6qwpstg01.grant.example.com -n $(NODES)
	./gen-repmgr-info -e uiopmno5qwpstg01.grant.example.com -n $(NODES)
	./gen-repmgr-info -e uiopmno6qwpstg01.grant.example.com -n $(NODES)
	./gen-repmgr-info -m			 -n $(NODES)
	./gen-repmgr-info -C uiopmno5qwpstg00.grant.example.com -n $(NODES)
	./gen-repmgr-info -C uiopmno5qwpstg01.grant.example.com -n $(NODES)
	./gen-repmgr-info -C uiopmno6qwpstg00.grant.example.com -n $(NODES)
	./gen-repmgr-info -C uiopmno6qwpstg01.grant.example.com -n $(NODES)
	./gen-repmgr-info -p -n $(NODES)

