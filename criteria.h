/*
 * Program:     Mailbox Access routines
 *              Extension of mail_criteria function
 *
 * Author:      Helena Gomes <hpgomes@mail.pt>
 * Date:        18 July 2001
 * Last Edited: 15 October 2001
 *
 * Parts of code from sources of c-client and imap (Mark Crispin)
 * Copyright 2001 University of Washington.
 */

SEARCHPGM *make_criteria(char *criteria);
long _parse_criterion(SEARCHPGM *pgm, char **arg, unsigned long maxmsg, unsigned long maxuid, unsigned long depth);
long _parse_criteria(SEARCHPGM *pgm, char **arg, unsigned long maxmsg, unsigned long maxuid, unsigned long depth);
long _crit_number(unsigned long *number, char **arg);
long _crit_set(SEARCHSET **set, char **arg, unsigned long maxima);
long _crit_string(STRINGLIST **string, char **arg);
char *_parse_astring(char **arg, unsigned long *size, char *del);
long _crit_date(unsigned short *date, char **arg);
long _crit_date_work(unsigned short *date, char **arg);
void _inliteral(char *s, unsigned long n);
void _slurp(char *s, int n);
