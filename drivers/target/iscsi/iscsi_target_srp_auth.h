#ifndef _ISCSI_SRP_H_
#define _ISCSI_SRP_H_

/*SRP Supported GROUPS */

#define SRP_DEFAULT_GROUP   1536
#define SRP_UNKNOWN_GROUP   0

/* The length of s,A,B,M and H(A | M | K) in binary form (not the length of
 the character string that represents them in
 encoded form) MUST not exceed 1024 bytes
*/
#define	MAX_SRP_PR_SIZE     1024
#define SRP_HASH_LENGTH     1024


/*SRP States*/
#define SRP_STAGE_CLIENT_U	1
#define SRP_STAGE_SERVER_GRPS	2

#define SRP_STAGE_CLIENT_GRPA	3
#define SRP_STAGE_SERVER_B  4

#define SRP_STAGE_CLIENT_M	5
#define SRP_STAGE_SERVER_HM 6

extern u32 srp_main_loop(struct iscsi_conn *, struct iscsi_node_auth *, char *, char *,
				int *, int *);

struct iscsi_srp {
	unsigned char	id;  /* do we need this ?  */

	unsigned char	grp_type;   /*SRP_GROUP*/
    unsigned char   user; /* SRP_u (user) */
    unsigned char   salt; /* SRP_s (salt) */
    unsigned char   srp_b; /* SRP_B */
    unsigned char   srp_m;  /* SRP_M */
	unsigned char	final_hash[SRP_HASH_LENGTH]; /* SRP_HM */
    unsigned char   target_auth; /* set this to 1 if AuthTarget=yes */
	unsigned int	srp_state;
} ____cacheline_aligned;

#endif   /*** _ISCSI_SRP_H_ ***/
