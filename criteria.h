/*
 * Program:     Mailbox Access routines
 *              Extension of mail_criteria function
 *
 * Author:      Helena Gomes <hpgomes@mail.pt>
 * Date:        18 July 2001
 * Last Edited: 23 July 2001
 *
 * Parts of code from sources of c-client (Mark Crispin)
 * Copyright 2001 University of Washington.
 */

long _mail_parse_number(MESSAGECACHE *elt, char *s);
long _mail_criteria_number (unsigned long *number);
SEARCHPGM *_mail_criteria (char *criteria);
SEARCHPGM *make_criteria(char *criteria);
