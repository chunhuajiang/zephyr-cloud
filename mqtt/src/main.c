#include <zephyr.h>
#include <stdio.h>
#include <net/mqtt.h>

#include <net/net_context.h>
#include <net/net_if.h>
#include <net/net_core.h>
#include <net/net_mgmt.h>

#include <misc/printk.h>
#include <string.h>
#include <errno.h>

#if defined(CONFIG_NET_L2_BLUETOOTH)
#include <bluetooth/bluetooth.h>
#include <bluetooth/conn.h>
#include <gatt/ipss.h>
#endif

#include "config.h"

#define CONN_TRIES 20

/* Container for some structures used by the MQTT publisher app. */
struct mqtt_client_ctx {
	/**
	 * The connect message structure is only used during the connect
	 * stage. Developers must set some msg properties before calling the
	 * mqtt_tx_connect routine. See below.
	 */
	struct mqtt_connect_msg connect_msg;
	/**
	 * This is the message that will be received by the server
	 * (MQTT broker).
	 */
	struct mqtt_publish_msg pub_msg;

	/**
	 * This is the MQTT application context variable.
	 */
	struct mqtt_ctx mqtt_ctx;

	/**
	 * This variable will be passed to the connect callback, declared inside
	 * the mqtt context struct. If not used, it could be set to NULL.
	 */
	void *connect_data;

	/**
	 * This variable will be passed to the disconnect callback, declared
	 * inside the mqtt context struct. If not used, it could be set to NULL.
	 */
	void *disconnect_data;

	/**
	 * This variable will be passed to the publish_tx callback, declared
	 * inside the mqtt context struct. If not used, it could be set to NULL.
	 */
	void *publish_data;
};

/* The mqtt client struct */
static struct mqtt_client_ctx client_ctx;

static struct net_mgmt_event_callback mgmt_cb;
static struct k_sem got_ip_sem;

/* This routine sets some basic properties for the network context variable */
static int network_setup(void);

#if defined(CONFIG_MQTT_LIB_TLS)

#include "test_certs.h"

/* TLS */
#define TLS_SNI_HOSTNAME "localhost"
#define TLS_REQUEST_BUF_SIZE 1500
#define TLS_PRIVATE_DATA "Zephyr TLS mqtt publisher"

static u8_t tls_request_buf[TLS_REQUEST_BUF_SIZE];

NET_STACK_DEFINE("mqtt_tls_stack", tls_stack,
		CONFIG_NET_APP_TLS_STACK_SIZE, CONFIG_NET_APP_TLS_STACK_SIZE);

NET_APP_TLS_POOL_DEFINE(tls_mem_pool, 30);

int setup_cert(struct net_app_ctx *ctx, void *cert)
{
#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
	mbedtls_ssl_conf_psk(&ctx->tls.mbedtls.conf,
			client_psk, sizeof(client_psk),
			(const unsigned char *)client_psk_id,
			sizeof(client_psk_id) - 1);
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
	{
		mbedtls_x509_crt *ca_cert = cert;
		int ret;

		ret = mbedtls_x509_crt_parse_der(ca_cert,
				ca_certificate,
				sizeof(ca_certificate));
		if (ret != 0) {
			NET_ERR("mbedtls_x509_crt_parse_der failed "
					"(-0x%x)", -ret);
			return ret;
		}

		/* mbedtls_x509_crt_verify() should be called to verify the
		 * cerificate in the real cases
		 */

		mbedtls_ssl_conf_ca_chain(&ctx->tls.mbedtls.conf,
				ca_cert, NULL);

		mbedtls_ssl_conf_authmode(&ctx->tls.mbedtls.conf,
				MBEDTLS_SSL_VERIFY_REQUIRED);

		mbedtls_ssl_conf_cert_profile(&ctx->tls.mbedtls.conf,
				&mbedtls_x509_crt_profile_default);
	}
#endif /* MBEDTLS_X509_CRT_PARSE_C */

	return 0;
}
#endif

/* The signature of this routine must match the connect callback declared at
 * the mqtt.h header.
 */
static void connect_cb(struct mqtt_ctx *mqtt_ctx)
{
	struct mqtt_client_ctx *client_ctx;

	client_ctx = CONTAINER_OF(mqtt_ctx, struct mqtt_client_ctx, mqtt_ctx);

	printk("[%s:%d]", __func__, __LINE__);

	if (client_ctx->connect_data) {
		printk(" user_data: %s",
		       (const char *)client_ctx->connect_data);
	}

	printk("\n");
}

/* The signature of this routine must match the disconnect callback declared at
 * the mqtt.h header.
 */
static void disconnect_cb(struct mqtt_ctx *mqtt_ctx)
{
	struct mqtt_client_ctx *client_ctx;

	client_ctx = CONTAINER_OF(mqtt_ctx, struct mqtt_client_ctx, mqtt_ctx);

	printk("[%s:%d]", __func__, __LINE__);

	if (client_ctx->disconnect_data) {
		printk(" user_data: %s",
		       (const char *)client_ctx->disconnect_data);
	}

	printk("\n");
}

/**
 * The signature of this routine must match the publish_tx callback declared at
 * the mqtt.h header.
 *
 * NOTE: we have two callbacks for MQTT Publish related stuff:
 *	- publish_tx, for publishers
 *	- publish_rx, for subscribers
 *
 * Applications must keep a "message database" with pkt_id's. So far, this is
 * not implemented here. For example, if we receive a PUBREC message with an
 * unknown pkt_id, this routine must return an error, for example -EINVAL or
 * any negative value.
 */
static int publish_cb(struct mqtt_ctx *mqtt_ctx, u16_t pkt_id,
		      enum mqtt_packet type)
{
	struct mqtt_client_ctx *client_ctx;
	const char *str;
	int rc = 0;

	client_ctx = CONTAINER_OF(mqtt_ctx, struct mqtt_client_ctx, mqtt_ctx);

	switch (type) {
	case MQTT_PUBACK:
		str = "MQTT_PUBACK";
		break;
	case MQTT_PUBCOMP:
		str = "MQTT_PUBCOMP";
		break;
	case MQTT_PUBREC:
		str = "MQTT_PUBREC";
		break;
	default:
		rc = -EINVAL;
		str = "Invalid MQTT packet";
	}

	printk("[%s:%d] <%s> packet id: %u", __func__, __LINE__, str, pkt_id);

	if (client_ctx->publish_data) {
		printk(", user_data: %s",
		       (const char *)client_ctx->publish_data);
	}

	printk("\n");

	return rc;
}

/**
 * The signature of this routine must match the malformed callback declared at
 * the mqtt.h header.
 */
static void malformed_cb(struct mqtt_ctx *mqtt_ctx, u16_t pkt_type)
{
	printk("[%s:%d] pkt_type: %u\n", __func__, __LINE__, pkt_type);
}

static void prepare_mqtt_publish_msg(struct mqtt_publish_msg *pub_msg,
				     enum mqtt_qos qos)
{
    static char buf[128];
    
    memset(buf, 0, sizeof(buf));
    sprintf(&buf[3], "{\"%s\":%d,\"%s\":%d}", "temperature", 32, "humidity", 55);
    uint16_t len = strlen(&buf[3]);
    buf[0] = 0x03;
    buf[1] = len >> 8;
    buf[2] = len & 0xFF;
	pub_msg->msg = buf;
	pub_msg->msg_len = len + 3;

	pub_msg->topic = "$dp";
	pub_msg->topic_len = strlen(client_ctx.pub_msg.topic);
	pub_msg->qos = qos;
	pub_msg->pkt_id = sys_rand32_get();
}

#define RC_STR(rc)	((rc) == 0 ? "OK" : "ERROR")

#define PRINT_RESULT(func, rc)	\
	printk("[%s:%d] %s: %d <%s>\n", __func__, __LINE__, \
	       (func), rc, RC_STR(rc))

/* In this routine we block until the connected variable is 1 */
static int try_to_connect(struct mqtt_client_ctx *client_ctx)
{
	int i = 0;

	while (i++ < APP_CONNECT_TRIES && !client_ctx->mqtt_ctx.connected) {
		int rc;

		rc = mqtt_tx_connect(&client_ctx->mqtt_ctx,
				     &client_ctx->connect_msg);
		k_sleep(APP_SLEEP_MSECS);
		PRINT_RESULT("mqtt_tx_connect", rc);
		if (rc != 0) {
			continue;
		}
	}

	if (client_ctx->mqtt_ctx.connected) {
		return 0;
	}

	return -EINVAL;
}

static void mqtt_demo(void)
{
	int i, rc;

	/* Set everything to 0 and later just assign the required fields. */
	memset(&client_ctx, 0x00, sizeof(client_ctx));

	/* connect, disconnect and malformed may be set to NULL */
	client_ctx.mqtt_ctx.connect = connect_cb;

	client_ctx.mqtt_ctx.disconnect = disconnect_cb;
	client_ctx.mqtt_ctx.malformed = malformed_cb;

	client_ctx.mqtt_ctx.net_init_timeout = APP_NET_INIT_TIMEOUT;
	client_ctx.mqtt_ctx.net_timeout = APP_TX_RX_TIMEOUT;

	client_ctx.mqtt_ctx.peer_addr_str = BROKER_ADDR;
	client_ctx.mqtt_ctx.peer_port = BROKER_PORT;

#if defined(CONFIG_MQTT_LIB_TLS)
	/** TLS setup */
	client_ctx.mqtt_ctx.request_buf = tls_request_buf;
	client_ctx.mqtt_ctx.request_buf_len = TLS_REQUEST_BUF_SIZE;
	client_ctx.mqtt_ctx.personalization_data = TLS_PRIVATE_DATA;
	client_ctx.mqtt_ctx.personalization_data_len = strlen(TLS_PRIVATE_DATA);
	client_ctx.mqtt_ctx.cert_host = TLS_SNI_HOSTNAME;
	client_ctx.mqtt_ctx.tls_mem_pool = &tls_mem_pool;
	client_ctx.mqtt_ctx.tls_stack = tls_stack;
	client_ctx.mqtt_ctx.tls_stack_size = K_THREAD_STACK_SIZEOF(tls_stack);
	client_ctx.mqtt_ctx.cert_cb = setup_cert;
	client_ctx.mqtt_ctx.entropy_src_cb = NULL;
#endif

	/* Publisher apps TX the MQTT PUBLISH msg */
	client_ctx.mqtt_ctx.publish_tx = publish_cb;

	/* The connect message will be sent to the MQTT server (broker).
	 * If clean_session here is 0, the mqtt_ctx clean_session variable
	 * will be set to 0 also. Please don't do that, set always to 1.
	 * Clean session = 0 is not yet supported.
	 */
	client_ctx.connect_msg.client_id = MQTT_CLIENTID;
	client_ctx.connect_msg.client_id_len = strlen(MQTT_CLIENTID);
	client_ctx.connect_msg.clean_session = 1;
    client_ctx.connect_msg.user_name = MQTT_USERNAME;
    client_ctx.connect_msg.user_name_len = strlen(MQTT_USERNAME);
    client_ctx.connect_msg.password = MQTT_PASSWORD;
    client_ctx.connect_msg.password_len = strlen(MQTT_PASSWORD);

	client_ctx.connect_data = "CONNECTED";
	client_ctx.disconnect_data = "DISCONNECTED";
	client_ctx.publish_data = "PUBLISH";

	rc = network_setup();
	PRINT_RESULT("network_setup", rc);
	if (rc < 0) {
		return;
	}

	rc = mqtt_init(&client_ctx.mqtt_ctx, MQTT_APP_PUBLISHER);
	PRINT_RESULT("mqtt_init", rc);
	if (rc != 0) {
		return;
	}

    k_sem_take(&got_ip_sem, K_FOREVER);
    
	for (i = 0; i < CONN_TRIES; i++) {
		rc = mqtt_connect(&client_ctx.mqtt_ctx);
		PRINT_RESULT("mqtt_connect", rc);
		if (!rc) {
			goto connected;
		}
	}

	goto exit_app;

connected:

	rc = try_to_connect(&client_ctx);
	PRINT_RESULT("try_to_connect", rc);
	if (rc != 0) {
		goto exit_app;
	}

	i = 0;
	while (i++ < APP_MAX_ITERATIONS) {
		rc = mqtt_tx_pingreq(&client_ctx.mqtt_ctx);
		k_sleep(APP_SLEEP_MSECS);
		PRINT_RESULT("mqtt_tx_pingreq", rc);

        prepare_mqtt_publish_msg(&client_ctx.pub_msg, MQTT_QoS0);
		rc = mqtt_tx_publish(&client_ctx.mqtt_ctx, &client_ctx.pub_msg);
		k_sleep(APP_SLEEP_MSECS);
		PRINT_RESULT("mqtt_tx_publish", rc);      
	}

	rc = mqtt_tx_disconnect(&client_ctx.mqtt_ctx);
	PRINT_RESULT("mqtt_tx_disconnect", rc);

exit_app:

	mqtt_close(&client_ctx.mqtt_ctx);

	printk("\nBye!\n");
}

#if defined(CONFIG_NET_L2_BLUETOOTH)
static bool bt_connected;

static
void bt_connect_cb(struct bt_conn *conn, u8_t err)
{
	bt_connected = true;
}

static
void bt_disconnect_cb(struct bt_conn *conn, u8_t reason)
{
	bt_connected = false;
	printk("bt disconnected (reason %u)\n", reason);
}

static
struct bt_conn_cb bt_conn_cb = {
	.connected = bt_connect_cb,
	.disconnected = bt_disconnect_cb,
};
#endif

static int network_setup(void)
{

#if defined(CONFIG_NET_L2_BLUETOOTH)
	const char *progress_mark = "/-\\|";
	int i = 0;
	int rc;

	rc = bt_enable(NULL);
	if (rc) {
		printk("bluetooth init failed\n");
		return rc;
	}

	ipss_init();
	bt_conn_cb_register(&bt_conn_cb);
	rc = ipss_advertise();
	if (rc) {
		printk("advertising failed to start\n");
		return rc;
	}

	printk("\nwaiting for bt connection: ");
	while (bt_connected == false) {
		k_sleep(250);
		printk("%c\b", progress_mark[i]);
		i = (i + 1) % (sizeof(progress_mark) - 1);
	}
	printk("\n");
#endif

	return 0;
}

static void dhcp_handler(struct net_mgmt_event_callback *cb,
		    u32_t mgmt_event,
		    struct net_if *iface)
{
	int i = 0;

	if (mgmt_event != NET_EVENT_IPV4_ADDR_ADD) {
		return;
	}

	for (i = 0; i < NET_IF_MAX_IPV4_ADDR; i++) {
		char buf[NET_IPV4_ADDR_LEN];

		if (iface->ipv4.unicast[i].addr_type != NET_ADDR_DHCP) {
			continue;
		}

		printk("Got ip address: %s\n",
			 net_addr_ntop(AF_INET,
				     &iface->ipv4.unicast[i].address.in_addr,
				     buf, sizeof(buf)));
		printk("Lease time: %u seconds\n", iface->dhcpv4.lease_time);
		printk("Subnet: %s\n",
			 net_addr_ntop(AF_INET, &iface->ipv4.netmask,
				       buf, sizeof(buf)));
		printk("Router: %s\n",
			 net_addr_ntop(AF_INET, &iface->ipv4.gw,
				       buf, sizeof(buf)));        

        k_sem_give(&got_ip_sem);
        
        break;
	}
}

void do_dhcpv4(void)
{
    struct net_if *iface;

	printk("Run dhcpv4 client\n");

    k_sem_init(&got_ip_sem, 0, 1);
    
	net_mgmt_init_event_callback(&mgmt_cb, dhcp_handler,
				     NET_EVENT_IPV4_ADDR_ADD);
	net_mgmt_add_event_callback(&mgmt_cb);

	iface = net_if_get_default();

	net_dhcpv4_start(iface);
}      

void main(void)
{
    do_dhcpv4();
    
	mqtt_demo();
}

