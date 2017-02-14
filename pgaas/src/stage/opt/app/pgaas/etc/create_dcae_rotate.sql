/*
    Copyright (C) 2017 AT&T Intellectual Property. All rights reserved. 

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this code except in compliance
    with the License. You may obtain a copy of the License
    at http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software  
    distributed under the License is distributed on an "AS IS" BASIS,  
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or  
    implied. See the License for the specific language governing  
    permissions and limitations under the License. 

*/
create table dcae_rotate (
    basetablename varchar(129) not null,	/* the base table name to derive other tables from */
    columnname varchar(64) not null,		/* which column name to use as the datestamp */
    count int,					/* how many periods to keep around */
    period varchar(20)				/* one of 'week', 'month' or 'day' */
);
