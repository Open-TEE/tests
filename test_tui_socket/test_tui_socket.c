#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "com_protocol.h"
#include "tee_logging.h"

const char* sock_path = "/tmp/open_tee_tui_display";

int main(int argc, char ** argv)
{
	struct sockaddr_un sock_addr;
	struct com_msg_ca_init_tee_conn init_msg;
	int sockfd;

	argc = argc;
	argv = argv;

	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd == -1) {
		OT_LOG(LOG_ERR, "Socket creation failed");
		return EXIT_FAILURE;
	}

	memset(&sock_addr, 0, sizeof(struct sockaddr_un));
	strncpy(sock_addr.sun_path, sock_path, sizeof(sock_addr.sun_path) - 1);
	sock_addr.sun_family = AF_UNIX;

	if (connect(sockfd,
		    (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_un)) == -1) {
		OT_LOG(LOG_ERR, "Failed to connect to TUI Socket")
		goto err;
	}

	/* Fill init message */
	init_msg.msg_hdr.msg_name = COM_MSG_NAME_CA_INIT_CONTEXT;
	init_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	init_msg.msg_hdr.sess_id = 0; /* ignored */

	/* Send init message to TEE */
	if (com_send_msg(sockfd, &init_msg, sizeof(struct com_msg_ca_init_tee_conn))
			!= sizeof(struct com_msg_ca_init_tee_conn)) {
		OT_LOG(LOG_ERR, "Failed to send context initialization msg");
		goto err;
	}

err:
	close(sockfd);

	return EXIT_SUCCESS;
}
