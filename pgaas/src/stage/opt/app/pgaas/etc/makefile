# Copyright (C) 2017 AT&T Intellectual Property. All rights reserved. 
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this code except in compliance
# with the License. You may obtain a copy of the License
# at http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software  
# distributed under the License is distributed on an "AS IS" BASIS,  
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or  
# implied. See the License for the specific language governing  
# permissions and limitations under the License. 


all:

STAGEDIR=/dev/null
DISTPATH=/opt/app/pgaas

CFGFILES= create_dcae_rotate.sql 

stage:
	rm -rf $(STAGEDIR)/$(DISTPATH)/etc
	mkdir -p $(STAGEDIR)/$(DISTPATH)/etc
	cp $(CFGFILES) $(STAGEDIR)/$(DISTPATH)/etc
