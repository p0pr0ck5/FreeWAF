#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define VALID_HEX(X) (((X >= '0')&&(X <= '9')) || ((X >= 'a')&&(X <= 'f')) || \
	((X >= 'A')&&(X <= 'F')))
#define ISODIGIT(X) ((X >= '0')&&(X <= '7'))

static unsigned char x2c(unsigned char *what) {
    register unsigned char digit;

    digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A') + 10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10 : (what[1] - '0'));

    return digit;
}

static unsigned char xsingle2c(unsigned char *what) {
    register unsigned char digit;

    digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A') + 10 : (what[0] - '0'));

    return digit;
}

int js_decode(unsigned char *input, long int input_len) {

	unsigned char *d = (unsigned char *)input;
	long int i, count;

	if (input == NULL) return -1;

	i = count = 0;
	while (i < input_len) {
		if (input[i] == '\\') {
			/* Character is an escape. */

			if (   (i + 5 < input_len) && (input[i + 1] == 'u')
					&& (VALID_HEX(input[i + 2])) && (VALID_HEX(input[i + 3]))
					&& (VALID_HEX(input[i + 4])) && (VALID_HEX(input[i + 5])) )
			{
				/* \uHHHH */

				/* Use only the lower byte. */
				*d = x2c(&input[i + 4]);

				/* Full width ASCII (ff01 - ff5e) needs 0x20 added */
				if (   (*d > 0x00) && (*d < 0x5f)
						&& ((input[i + 2] == 'f') || (input[i + 2] == 'F'))
						&& ((input[i + 3] == 'f') || (input[i + 3] == 'F')))
				{
					(*d) += 0x20;
				}

				d++;
				count++;
				i += 6;
			}
			else if (   (i + 3 < input_len) && (input[i + 1] == 'x')
					&& VALID_HEX(input[i + 2]) && VALID_HEX(input[i + 3])) {
				/* \xHH */
				*d++ = x2c(&input[i + 2]);
				count++;
				i += 4;
			}
			else if ((i + 1 < input_len) && ISODIGIT(input[i + 1])) {
				unsigned char *orig_input = input;
				/* \OOO (only one byte, \000 - \377) */
				char input[4];
				int j = 0;

				while((i + 1 + j < input_len)&&(j < 3)) {
					input[j] = orig_input[i + 1 + j];
					j++;
					if (!ISODIGIT(orig_input[i + 1 + j])) break;
				}
				input[j] = '\0';

				if (j > 0) {
					if ((j == 3) && (input[0] > '3')) {
						j = 2;
						input[j] = '\0';
					}
					*d++ = (unsigned char)strtol(input, NULL, 8);
					i += 1 + j;
					count++;
				}
			}
			else if (i + 1 < input_len) {
				/* \C */
				unsigned char c = input[i + 1];
				switch(input[i + 1]) {
					case 'a' :
						c = '\a';
						break;
					case 'b' :
						c = '\b';
						break;
					case 'f' :
						c = '\f';
						break;
					case 'n' :
						c = '\n';
						break;
					case 'r' :
						c = '\r';
						break;
					case 't' :
						c = '\t';
						break;
					case 'v' :
						c = '\v';
						break;
						/* The remaining (\?,\\,\',\") are just a removal
						 * of the escape char which is default.
						 */
				}

				*d++ = c;
				i += 2;
				count++;
			}
			else {
				/* Not enough bytes */
				while(i < input_len) {
					*d++ = input[i++];
					count++;
				}
			}
		}
		else {
			*d++ = input[i++];
			count++;
		}
	}

	*d = '\0';

	return d - input;
}

int css_decode(unsigned char *input, long int input_len) {

    unsigned char *d = (unsigned char *)input;
    long int i, j, count;

    if (input == NULL) return -1;

    i = count = 0;
    while (i < input_len) {

        /* Is the character a backslash? */
        if (input[i] == '\\') {

            /* Is there at least one more byte? */
            if (i + 1 < input_len) {
                i++; /* We are not going to need the backslash. */

                /* Check for 1-6 hex characters following the backslash */
                j = 0;
                while (    (j < 6)
                        && (i + j < input_len)
                        && (VALID_HEX(input[i + j])))
                {
                    j++;
                }

                if (j > 0) { /* We have at least one valid hexadecimal character. */
                    int fullcheck = 0;

                    /* For now just use the last two bytes. */
                    switch (j) {
                        /* Number of hex characters */
                        case 1:
                            *d++ = xsingle2c(&input[i]);
                            break;

                        case 2:
                        case 3:
                            /* Use the last two from the end. */
                            *d++ = x2c(&input[i + j - 2]);
                            break;

                        case 4:
                            /* Use the last two from the end, but request
                             * a full width check.
                             */
                            *d = x2c(&input[i + j - 2]);
                            fullcheck = 1;
                            break;

                        case 5:
                            /* Use the last two from the end, but request
                             * a full width check if the number is greater
                             * or equal to 0xFFFF.
                             */
                            *d = x2c(&input[i + j - 2]);

                            /* Do full check if first byte is 0 */
                            if (input[i] == '0') {
                                fullcheck = 1;
                            }
                            else {
                                d++;
                            }
                            break;

                        case 6:
                            /* Use the last two from the end, but request
                             * a full width check if the number is greater
                             * or equal to 0xFFFF.
                             */
                            *d = x2c(&input[i + j - 2]);

                            /* Do full check if first/second bytes are 0 */
                            if (    (input[i] == '0')
                                    && (input[i + 1] == '0')
                               ) {
                                fullcheck = 1;
                            }
                            else {
                                d++;
                            }
                            break;
                    }

                    /* Full width ASCII (0xff01 - 0xff5e) needs 0x20 added */
                    if (fullcheck) {
                        if (   (*d > 0x00) && (*d < 0x5f)
                                && ((input[i + j - 3] == 'f') ||
                                    (input[i + j - 3] == 'F'))
                                && ((input[i + j - 4] == 'f') ||
                                    (input[i + j - 4] == 'F')))
                        {
                            (*d) += 0x20;
                        }

                        d++;
                    }

                    /* We must ignore a single whitespace after a hex escape */
                    if ((i + j < input_len) && isspace(input[i + j])) {
                        j++;
                    }

                    /* Move over. */
                    count++;
                    i += j;
                }

                /* No hexadecimal digits after backslash */
                else if (input[i] == '\n') {
                    /* A newline character following backslash is ignored. */
                    i++;
                }

                /* The character after backslash is not a hexadecimal digit, nor a newline. */
                else {
                    /* Use one character after backslash as is. */
                    *d++ = input[i++];
                    count++;
                }
            }

            /* No characters after backslash. */
            else {
                /* Do not include backslash in output (continuation to nothing) */
                i++; 
            }
        }

        /* Character is not a backslash. */
        else {
            /* Copy one normal character to output. */
            *d++ = input[i++];
            count++;
        }
    }

    /* Terminate output string. */
    *d = '\0';

    return d - input;
}

