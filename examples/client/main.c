/**
 * @file main.c
 * @author adarsh.raghoothaman@st.ovgu.de
 * @brief
 * @version 0.1
 * @date 2022-02-16
 *
 * @copyright Copyright (c) 2022
 *
 */
#include <stdio.h>
#include <string.h>
#include "msg.h"
#include "shell.h"
#include "fmt.h"
/*header for client functionalities*/
#include "doriot_wot_cl.h"


#define MAIN_QUEUE_SIZE (4)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

extern int client_cmd_app(int argc, char **argv);
extern int find_cert_cmd_app(int argc, char **argv);
extern int delete_cert_cmd_app(int argc, char **argv);


static const shell_command_t shell_commands[] = {
    { "client", "client commands app", client_cmd_app },
    { "find", "find cert from list", find_cert_cmd_app },
    { "del", "delete a cert from list", delete_cert_cmd_app },
    { NULL, NULL, NULL }
};

static unsigned char og_priv_key_client[] = {
    0x41, 0x90, 0xA3, 0xC1, 0xD0, 0x09, 0xD7, 0x74, 0x96, 0x6B, 0x53, 0x51, 0x2E, 0x76, 0xDF, 0x5A,
    0x40, 0x1B, 0xE3, 0x4F, 0xBA, 0x55, 0x8C, 0x13, 0x26, 0xE2, 0x7F, 0xDD, 0xCB, 0x6A, 0xDE, 0x06

};

static unsigned char og_pub_key_client[] = {
    0x46, 0x96, 0xFA, 0xCD, 0x14, 0xE9, 0xE3, 0x76, 0x28, 0x35, 0x94, 0x89, 0x9D, 0x48, 0x19, 0x74,
    0x0E, 0x25, 0x0E, 0x75, 0xF5, 0x2C, 0xB3, 0x29, 0x19, 0xFB, 0x5B, 0x80, 0x2B, 0x8F, 0xC0, 0xD7,
    0x2B, 0x9E, 0x09, 0x67, 0x37, 0x88, 0xCC, 0x69, 0xF4, 0xA9, 0xA9, 0x32, 0x60, 0xE5, 0x75, 0x88,
    0x22, 0x0C, 0x2C, 0xD9, 0x34, 0x55, 0x7E, 0xC3, 0x0E, 0xDA, 0x33, 0x5D, 0x77, 0x16, 0xA6, 0x78,

};

static unsigned char psk_key[] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};


static void _set_credentials(wot_credentials_t *credentials)
{
    memcpy(credentials->private_key, og_priv_key_client, sizeof(og_priv_key_client));
    memcpy(credentials->public_key, og_pub_key_client, sizeof(og_pub_key_client));
    memcpy(credentials->psk_key, psk_key, sizeof(psk_key));
}


int main(void)
{
    puts("wot cert exchange client\n");
    /*provide key pair to the module*/
    wot_credentials_t credentials;
    _set_credentials(&credentials);
    wot_provision_keys(&credentials);

    /* for the thread running the shell */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should never be reached */
    return 0;
}
