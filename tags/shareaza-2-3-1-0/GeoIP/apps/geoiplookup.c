/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 2; tab-width: 2 -*- */
/* geoiplookup.c
 *
 * Copyright (C) 2006 MaxMind LLC
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <GeoIP.h>
#include <GeoIPCity.h>
#include <GeoIP_internal.h>
void geoiplookup(GeoIP* gi,char *hostname,int i);

void usage() {
	fprintf(stderr,"Usage: geoiplookup [-v] <ipaddress|hostname>\n");
}

int main (int argc, char *argv[]) {
	char * hostname = NULL;
	char * db_info;
	GeoIP * gi;
	int i;
	char *custom_directory = NULL;
	char *custom_file = NULL;

	if (argc < 2) {
		usage();
		exit(1);
	} 
	i = 1;
	while (i < argc) {
		if (strcmp(argv[i],"-v") == 0) {
			gi = GeoIP_new(GEOIP_STANDARD);
			if (gi != NULL) {
				db_info = GeoIP_database_info(gi);
				printf("%s\n",db_info);
				free(db_info);
				GeoIP_delete(gi);
				exit(0);
			} else {
				printf("error opening database\n");
				exit(0);
			}
		} else if (strcmp(argv[i],"-f") == 0) {
			if ((i+1) < argc){
				i++;
				custom_file = argv[i];
			}
		} else if (strcmp(argv[i],"-d") == 0) {
			if ((i+1) < argc){
				i++;
				custom_directory = argv[i];
			}
		} else {
			hostname = argv[i];
		}
		i++;
	}
	if (hostname == NULL) {
		usage();
		exit(1);
	}

	if (custom_file != NULL) {
		GeoIP_setup_custom_directory(custom_directory);
	}
	_GeoIP_setup_dbfilename();

	if (custom_file != NULL) {
		gi = GeoIP_open(custom_file, GEOIP_STANDARD);
		i = GeoIP_database_edition(gi);
		if (NULL == gi) {
			printf("%s not available, skipping...\n", GeoIPDBDescription[i]);
		} else {
			geoiplookup(gi,hostname,i);
		}
		GeoIP_delete(gi);
	} else {
		/* iterate through different database types */
		for (i = 0; i < NUM_DB_TYPES; ++i) {
			if (GeoIP_db_avail(i)) {
				gi = GeoIP_open_type(i, GEOIP_STANDARD);
				if (NULL == gi) {
					printf("%s not available, skipping...\n", GeoIPDBDescription[i]);
				} else {
					geoiplookup(gi,hostname,i);
				}
				GeoIP_delete(gi);
			}
		}
	}
	return 0;
}

void geoiplookup(GeoIP* gi,char *hostname,int i) {
	const char * country_code;
	const char * country_name;
	const char * domain_name;
	int netspeed;
	int country_id;
	GeoIPRegion * region;
	GeoIPRecord * gir;
	const char * org;
	if (GEOIP_DOMAIN_EDITION == i) {
		domain_name = GeoIP_name_by_name(gi,hostname);
		if (domain_name == NULL) {
			printf("%s: IP Address not found\n", GeoIPDBDescription[i]);
		} else {
			printf("%s: %s\n", GeoIPDBDescription[i], domain_name);
		}
	}
	if (GEOIP_COUNTRY_EDITION == i) {
		country_id = GeoIP_id_by_name(gi, hostname);
		country_code = GeoIP_country_code[country_id];
		country_name = GeoIP_country_name[country_id];
		if (country_code == NULL) {
			printf("%s: IP Address not found\n", GeoIPDBDescription[i]);
		} else {
			printf("%s: %s, %s\n", GeoIPDBDescription[i], country_code, country_name);
		}
	} else if (GEOIP_REGION_EDITION_REV0 == i || GEOIP_REGION_EDITION_REV1 == i) {
		region = GeoIP_region_by_name(gi, hostname);
		if (NULL == region) {
			printf("%s: IP Address not found\n", GeoIPDBDescription[i]);
		} else {
			printf("%s: %s, %s\n", GeoIPDBDescription[i], region->country_code, region->region);
		}
	} else if (GEOIP_CITY_EDITION_REV0 == i) {
		gir = GeoIP_record_by_name(gi, hostname);
		if (NULL == gir) {
			printf("%s: IP Address not found\n", GeoIPDBDescription[i]);
		} else {
			printf("%s: %s, %s, %s, %s, %f, %f\n", GeoIPDBDescription[i], gir->country_code, gir->region,
                                                               gir->city, gir->postal_code,gir->latitude, gir->longitude);
		}
	} else if (GEOIP_CITY_EDITION_REV1 == i) {
		gir = GeoIP_record_by_name(gi, hostname);
		if (NULL == gir) {
			printf("%s: IP Address not found\n", GeoIPDBDescription[i]);
		} else {
			printf("%s: %s, %s, %s, %s, %f, %f, %d, %d\n", GeoIPDBDescription[i], gir->country_code, gir->region, gir->city, gir->postal_code,
						 gir->latitude, gir->longitude, gir->dma_code, gir->area_code);
		}
	} else if (GEOIP_ORG_EDITION == i || GEOIP_ISP_EDITION == i) {
		org = GeoIP_org_by_name(gi, hostname);
		if (org == NULL) {
			printf("%s: IP Address not found\n", GeoIPDBDescription[i]);
		} else {
			printf("%s: %s\n", GeoIPDBDescription[i], org);
		}
	} else if (GEOIP_NETSPEED_EDITION == i) {
		netspeed = GeoIP_id_by_name (gi, hostname);
                if (netspeed == GEOIP_UNKNOWN_SPEED) {
			printf("%s: Unknown\n", GeoIPDBDescription[i]);
		} else if (netspeed == GEOIP_DIALUP_SPEED) {
			printf("%s: Dialup\n", GeoIPDBDescription[i]);
		} else if (netspeed == GEOIP_CABLEDSL_SPEED) {
			printf("%s: Cable/DSL\n", GeoIPDBDescription[i]);
		} else if (netspeed == GEOIP_CORPORATE_SPEED) {
			printf("%s: Corporate\n", GeoIPDBDescription[i]);
		}
	}
}
