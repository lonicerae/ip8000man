/***************************************************************************
 * Project: ip8000man
 * File:    main.c
 *
 * Copyright (C) 2016 Flos Guo <qguo@redhat.com>
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, visit the http://fsf.org website.
 *
 * ChangeLog:
 *   2016-05-01, v0.0.1
 *     Based on the black-box analysis. power on/off and reset now works.
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <curl/curl.h>

static const char *opt_string = "H:U:P:v";

/* URL length */
#define URLLEN 512

#define log_dbg(fmt, args...) { \
    fprintf(stdout, "[%s:%d] " fmt , __FILE__ , __LINE__ , ## args ); \
}

#define log_err(fmt, args...) { \
    fprintf(stderr, fmt, ## args); \
}

const char *page[] = {
    "view.htm",
    "power.htm",
    "logout.htm"
};

enum page_id {
    PG_VIEW = 0,
    PG_POWER,
    PG_LOGOUT,
    PG_LAST
};

int make_url(char *dist, size_t n, const char *hostname, const char *page, const char *pid)
{
    int ret = 0;
    char *p = dist;

    memset(p, 0, n);

    if (strlen(pid) > 0) {
        ret = sprintf(p, "https://%s/%s?%s", hostname, page, pid);
    }
    else {
        ret = sprintf(p, "https://%s/%s", hostname, page);
    }
#if 0
    log_dbg("url size: %d, dist size:%lu\n", ret, n);
#endif

    if (ret < 0) return ret;

    /* over commit ? */
    if ((size_t)ret >= n) {
        ret = -1;
    }
    return ret;
}

void usage()
{
    const char *usage[] = {
        "ip8000man v0.0.1 COPYRIGHT(c) 2016 Flos Guo\n",
        "  - Usage: [-v] -H <host> -U <username> -P <password> <command>\n",
        "  - Supported commands: power, reset\n"
    };
    printf("%s%s%s", usage[0], usage[1], usage[2]);
    exit(1);
}

static int ret_value = 0;

int main(int argc, char **argv)
{
    CURL *curl;
    CURLcode res;

    char current_page[URLLEN];
    char *redirect_url = NULL;

    /* output */
    FILE *fd_pg;

    /* split string */
    char *delimeter = "?";
    char *sp;

    /* id */
    char pid[64] = {0};

    /* used for post data */
    char post_data[128] = {0};

    char hostname[256] = {0};
    char username[32] = {0};
    char password[32] = {0};
    char cmd[16] = {0};

    /* debug option */
    long verbose = 0;

    int opt = 0;

    if (argc < 2) {
        usage();
        exit(1);
    }

    while ((opt = getopt(argc, argv, opt_string)) != -1) {
        switch (opt) {
        case 'H':
            if (strlen(optarg) >= 256) {
                log_err("Hostname too long.\n");
                exit(1);
            }
            strcpy(hostname, optarg);
            break;

        case 'U':
            if (strlen(optarg) >= 32) {
                log_err("Username too long.\n");
                exit(1);
            }
            strcpy(username, optarg);
            break;

        case 'P':
            if (strlen(optarg) >= 32) {
                log_err("Password too long\n");
                exit(1);
            }
            strcpy(password, optarg);
            break;

        case 'v':
            verbose = 1L;
            break;

        case '?':
            log_err("Illegal option: -%c\n\n", isprint(optopt) ? optopt : '#');
            usage();
            break;

        default:
            log_err("Unsupport option.\n\n");
            usage();
            break;
        }
    }

    if (!strlen(hostname) || !strlen(username) || !strlen(password)) {
        usage();
    }

    /* check the command */
    if (argc-optind > 0) {
        if (strcmp("power", argv[optind]) == 0) {
            strcpy(cmd, "onoff");
        }
        else if (strcmp("reset", argv[optind]) == 0) {
            strcpy(cmd, "reset");
        }
        else {
            log_err("Illegal command.\n\n");
            usage();
        }
    }
    else {
        log_err("No command specified.\n\n");
        usage();
    }

    if (verbose == 1L) {
        log_dbg("hostname:%s, username:%s, password:%s, command:%s\n", hostname, username, password, cmd);
    }

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (curl) {
        /****************************************
         *    view page. no pid string atm      *
         ****************************************/
        if (make_url(current_page, sizeof(current_page), hostname, page[PG_VIEW], "") < 0) {
            log_err("ERROR: failed to make url %s\n", page[PG_VIEW]);
            goto CLEAN;
        }
        if (verbose == 1L) {
            log_dbg("view url:%s\n", current_page);
        }

        if (verbose == 1L) {
            fd_pg = fopen("/tmp/ip8000man.log", "w");
        }
        else {
            fd_pg = fopen("/dev/null", "w");
        }
        if (!fd_pg) {
            log_err("ERROR: failed to open log file\n");
            goto CLEAN;
        }

        curl_easy_setopt(curl, CURLOPT_URL, current_page);

        /* post data */
        sprintf(post_data, "password=%s&username=%s", password, username);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, verbose);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fd_pg);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            log_err("ERROR: %s\n", curl_easy_strerror(res));
            goto CLEAN;
        }

        /* get redirect url */
        res = curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redirect_url);
        if (res != CURLE_OK) {
            log_err("ERROR: %s\n", curl_easy_strerror(res));
            goto CLEAN;
        }
        if (verbose == 1L) {
            log_dbg("redirect url:%s\n", redirect_url);
        }

        /*
         * extract the pid value from the redirect_url
         */
        sp = strtok(redirect_url, delimeter);
        sp = strtok(NULL, delimeter);
        if (!sp || !strlen(sp)) {
            log_err("ERROR: failed to get pid\n");
            goto CLEAN;
        }
        if (strlen(sp) >= 64) {
            log_err("ERROR: pid too long\n");
            goto CLEAN;
        }
        /* check pid format and if login successfully */
        if (strncmp("pid=", sp, 4) == 0) {
            strcpy(pid, sp);
        }
        else if (strcmp("cmd=fail", sp) == 0) {
            log_err("ERROR: login failed, wrong username or password.\n");
            ret_value = -1;
            goto CLEAN;
        }
        else {
            log_err("ERROR: wrong pid format: %s\n", sp);
            goto CLEAN;
        }

        /****************************************
         *              power page              *
         ****************************************/
        if (make_url(current_page, sizeof(current_page), hostname, page[PG_POWER], pid) < 0) {
            log_err("ERROR: failed to make url %s\n", page[PG_POWER]);
            goto CLEAN;
        }
        if (verbose == 1L) {
            log_dbg("power url:%s\n", current_page);
        }

        curl_easy_setopt(curl, CURLOPT_URL, current_page);

        /* command */
        memset(post_data, 0, sizeof(post_data));
        sprintf(post_data, "cmd_id=%s&", cmd);
        strcat(post_data, (const char *)pid);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            log_err("ERROR: %s\n", curl_easy_strerror(res));
            goto CLEAN;
        }

        /****************************************
         *             logout page              *
         ****************************************/
        if (make_url(current_page, sizeof(current_page), hostname, page[PG_LOGOUT], pid) < 0) {
            log_err("ERROR: failed to make url %s\n", page[PG_LOGOUT]);
            goto CLEAN;
        }
        if (verbose == 1L) {
            log_dbg("logout url:%s\n", current_page);
        }

        curl_easy_setopt(curl, CURLOPT_URL, current_page);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            log_err("ERROR: %s\n", curl_easy_strerror(res));
            goto CLEAN;
        }

CLEAN:
        if (fd_pg) fclose(fd_pg);
        curl_easy_cleanup(curl);
    }
    else {
        log_err("Failed to init curl\n");
        ret_value = -1;
    }
    curl_global_cleanup();
    return ret_value;
}
