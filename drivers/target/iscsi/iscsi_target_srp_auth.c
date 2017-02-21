#include <crypto/hash.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/scatterlist.h>

#include <target/iscsi/iscsi_target_core.h>
#include "iscsi_target_nego.h"
#include "iscsi_target_srp_auth.h"

/* This functions is usable */
static int srp_check_group(const char *grp_str)
{
	char *tmp, *orig, *token;

	tmp = kstrdup(a_str, GFP_KERNEL);
	if (!tmp) {
		pr_err("Memory allocation failed for SRP_GROUP temporary buffer\n");
		return SRP_UNKNOWN_GROUP;
	}
	orig = tmp;

	token = strsep(&tmp, "=");
	if (!token)
		goto out;

	if (strcmp(token, "SRP_GROUP")) {
		pr_err("Unable to locate SRP_GROUP key\n");
		goto out;
	}
	while (token) {
		token = strsep(&tmp, ",");
		if (!token)
			goto out;

		if (!strncmp(token, "SRP-1536", 1)) {
			pr_debug("Selected SRP-1536 group\n");
			kfree(orig);
			return SRP_DEFAULT_GROUP;
		}
	}
out:
	kfree(orig);
	return SRP_UNKNOWN_GROUP;
}

/* This function is usable */
static void srp_close(struct iscsi_conn *conn)
{
	kfree(conn->auth_protocol);
	conn->auth_protocol = NULL;
}


static struct iscsi_srp *srp_server_open(
	struct iscsi_conn *conn,
	struct iscsi_node_auth *auth,
	const char *grp_str,
	char *grps_str,
	unsigned int *grps_len)
{
	int ret;
	struct iscsi_srp *srp;
    // Check if the SRP user name and password is set.
	if (!(auth->naf_flags & NAF_USERID_SET) ||
	    !(auth->naf_flags & NAF_PASSWORD_SET)) {
		pr_err("SRP user or password not set for"
				" Initiator ACL\n");
		return NULL;
	}

    //Fill-in the login details here.
	conn->auth_protocol = kzalloc(sizeof(struct iscsi_srp), GFP_KERNEL);
	if (!conn->auth_protocol)
		return NULL;

	srp = conn->auth_protocol;
    // set_srp_user
    // Check if the username matches that is set on the target side.
    // set authenticate target if TargetAuth=yes
    // send response here with "SRP_GROUP=SRP-1536 SRP_s =<s>"
    *grps_len = 0;
    /* This should be implemented better */
    *grps_len += sprintf(grps_str,"SRP_GROUP=SRP-1536 SRP_s=%s", srp->user);
    *grps_len += 1;
	/*
	 * Set Identifier.
	srp->id = conn->tpg->tpg_srp_id++;
	*grps_len += sprintf(grps_str + *grps_len, "SRP_I=%d", srp->id);
	*grps_len += 1;
	pr_debug("[server] Sending SRP_I=%d\n", srp->id);
	 */
	return srp;
}

/*Needs porting*/
u32 srp_main_loop(
	struct iscsi_conn *conn,
	struct iscsi_node_auth *auth,
	char *in_text,
	char *out_text,
	int *in_len,
	int *out_len)
{
	struct iscsi_srp *srp = conn->auth_protocol;

	if (!srp) {
		srp = srp_server_open(conn, auth, in_text, out_text, out_len);
		if (!srp)
			return 2;
		srp->srp_state = SRP_STAGE_SERVER_AIC;
		return 0;
	} else if (srp->srp_state == SRP_STAGE_SERVER_AIC) {
		convert_null_to_semi(in_text, *in_len);
		if (srp_got_response(conn, auth, in_text, out_text,
				out_len) < 0) {
			srp_close(conn);
			return 2;
		}
		if (auth->authenticate_target)
			srp->srp_state = SRP_STAGE_SERVER_NR;
		else
			*out_len = 0;
		srp_close(conn);
		return 1;
	}

	return 2;
}
