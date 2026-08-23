--- usr.sbin/smtpd/smtp_session.c.orig	2026-08-23 18:44:31 UTC
+++ usr.sbin/smtpd/smtp_session.c
@@ -311,6 +311,67 @@ static struct tree wait_filter_fd;
 static struct tree wait_filters;
 static struct tree wait_filter_fd;
 
+/* Taken from https://www.cl.cam.ac.uk/~mgk25/ucs/utf8_check.c, reflowed to
+ * match OpenSMTPD's style.
+ */
+static int
+is_valid_utf8(const char *buf)
+{
+	const unsigned char *s = (const unsigned char *)buf;
+
+	while (*s)
+	{
+		if (*s < 0x80)
+		{
+			/* 0xxxxxxx */
+			s++;
+		}
+		else if ((s[0] & 0xe0) == 0xc0)
+		{
+			/* 110XXXXx 10xxxxxx */
+			if ((s[1] & 0xc0) != 0x80 ||
+			    /* overlong? */
+			    (s[0] & 0xfe) == 0xc0)
+				return 0;
+			else
+				s += 2;
+		}
+		else if ((s[0] & 0xf0) == 0xe0)
+		{
+			/* 1110XXXX 10Xxxxxx 10xxxxxx */
+			if ((s[1] & 0xc0) != 0x80 ||
+			    (s[2] & 0xc0) != 0x80 ||
+			    /* overlong? */
+			    (s[0] == 0xe0 && (s[1] & 0xe0) == 0x80) ||
+			    /* surrogate? */
+			    (s[0] == 0xed && (s[1] & 0xe0) == 0xa0) ||
+			    /* U+FFFE or U+FFFF? */
+			    (s[0] == 0xef && s[1] == 0xbf && (s[2] & 0xfe) == 0xbe))
+				return 0;
+			else
+				s += 3;
+		}
+		else if ((s[0] & 0xf8) == 0xf0)
+		{
+			/* 11110XXX 10XXxxxx 10xxxxxx 10xxxxxx */
+			if ((s[1] & 0xc0) != 0x80 ||
+			    (s[2] & 0xc0) != 0x80 ||
+			    (s[3] & 0xc0) != 0x80 ||
+			    /* overlong? */
+			    (s[0] == 0xf0 && (s[1] & 0xf0) == 0x80) ||
+			    /* > U+10FFFF? */
+			    (s[0] == 0xf4 && s[1] > 0x8f) || s[0] > 0xf4)
+				return 0;
+			else
+				s += 4;
+		}
+		else
+			return 0;
+	}
+
+	return 1;
+}
+
 static void
 header_append_domain_buffer(char *buffer, char *domain, size_t len)
 {
@@ -1987,6 +2048,9 @@ smtp_rfc4954_auth_plain(struct smtp_session *s, char *
 		pass++; /* skip NUL */
 		if (pass[strcspn(pass, "\r\n")] != '\0')
 			goto abort;
+		if (!is_valid_utf8(user) || !is_valid_utf8(pass))
+			goto abort;
+
 
 		m_create(p_lka,  IMSG_SMTP_AUTHENTICATE, 0, 0, -1);
 		m_add_id(p_lka, s->id);
