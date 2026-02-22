#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/genetlink.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include "../include/netlink_ch.h"
#include "../include/crypto.h"

/* forward declarations */
static int photon_handle_register(struct sk_buff *skb, struct genl_info *info);
static int photon_handle_key_exchange(struct sk_buff *skb, struct genl_info *info);

/* registered listener tracking */
#define MAX_LISTENERS 16

struct photon_listener {
    u32 portid; // netlink port ID
    pid_t pid;
    bool verified;
    u64 registered_at; // timestamp of registration
};

static struct photon_listener g_listeners[MAX_LISTENERS];
static int g_num_listeners = 0;
static DEFINE_SPINLOCK(listeners_lock);

/* generic netlink family */
static struct genl_family photon_genl_family;

/* multicast group */
static struct genl_multicast_group photon_mcgrps[] = {
    { .name = PHOTON_RING_MCGRP_NAME, },
};

/* generic netlink operations */
static const struct genl_ops photon_genl_ops[] = {
    {
        .cmd = PHOTON_CMD_REGISTER,
        .doit = photon_handle_register,
        .flags = GENL_ADMIN_PERM,
    },
    {
        .cmd = PHOTON_CMD_KEY_EXCHANGE,
        .doit = photon_handle_key_exchange,
        .flags = GENL_ADMIN_PERM,
    },
};

/* netlink attribute policy */
static struct nla_policy photon_genl_policy[PHOTON_ATTR_MAX + 1] = {
    [PHOTON_ATTR_ENCRYPTED_DATA] = { .type = NLA_BINARY, .len = PHOTON_MAX_MSG_SIZE },
    [PHOTON_ATTR_IV] = { .type = NLA_BINARY, .len = 12 },
    [PHOTON_ATTR_AUTH_TAG] = { .type = NLA_BINARY, .len = 16 },
    [PHOTON_ATTR_SEQUENCE] = { .type = NLA_U64 },
    [PHOTON_ATTR_ROTATION_NUM] = { .type = NLA_U64 },
    [PHOTON_ATTR_TIMESTAMP] = { .type = NLA_U64 },
    [PHOTON_ATTR_PUBLIC_KEY] = { .type = NLA_BINARY, .len = 256 },
    [PHOTON_ATTR_ENCRYPTED_KEY] = { .type = NLA_BINARY, .len = 256 },
};

/* generic netlink family definition */
static struct genl_family photon_genl_family = {
    .name = PHOTON_RING_GENL_NAME,
    .version = PHOTON_RING_GENL_VERSION,
    .maxattr = PHOTON_ATTR_MAX,
    .policy = photon_genl_policy,
    .module = THIS_MODULE,
    .ops = photon_genl_ops,
    .n_ops = ARRAY_SIZE(photon_genl_ops),
    .mcgrps = photon_mcgrps,
    .n_mcgrps = ARRAY_SIZE(photon_mcgrps),
};

/**
 * photon_handle_register - handle listener registration request
 * @skb: socket buffer
 * @info: generic netlink info
 * 
 * userspace calls this to register as a listener for events.
 * Performs authentication and adds to listener list.
 */
static int photon_handle_register(struct sk_buff *skb, struct genl_info *info)
{
    u32 portid;
    pid_t pid;
    int ret;
    int i;
    unsigned long flags;

    if (!info)
        return -EINVAL;
    
    portid = info->snd_portid;
    pid = (pid_t)portid; // for userspace portid == pid

    printk(KERN_INFO "[PHOTON RING] Registration request from PID %d (portid %u)\n",
           pid, portid);
    
    // add to listener list
    spin_lock_irqsave(&listeners_lock, flags);

    // check if already registered
    for (i = 0; i < g_num_listeners; i++) {
        if (g_listeners[i].portid == portid) {
            printk(KERN_INFO "[PHOTON RING] PID %d already registered, updating\n", pid);
            g_listeners[i].pid = pid;
            g_listeners[i].verified = true;
            g_listeners[i].registered_at = ktime_get_real_ns();
            spin_unlock_irqrestore(&listeners_lock, flags);
            
            printk(KERN_INFO "[PHOTON RING] Listener %d re-registered successfully\n", pid);
            return 0;
        }
    }

    // add new listener
    if (g_num_listeners >= MAX_LISTENERS) {
        spin_unlock_irqrestore(&listeners_lock, flags);
        printk(KERN_ERR "[PHOTON RING] Maximum listeners reached (%d)\n", MAX_LISTENERS);
        return -ENOSPC;
    }
    
    i = g_num_listeners;
    g_listeners[i].portid = portid;
    g_listeners[i].pid = pid;
    g_listeners[i].verified = true;
    g_listeners[i].registered_at = ktime_get_real_ns();
    g_num_listeners++;
    
    spin_unlock_irqrestore(&listeners_lock, flags);
    
    printk(KERN_INFO "[PHOTON RING] Listener registered successfully\n");
    printk(KERN_INFO "[PHOTON RING]   PID: %d\n", pid);
    printk(KERN_INFO "[PHOTON RING]   Total listeners: %d\n", g_num_listeners);
    
    return 0;
}

/**
 * photon_handle_key_exchange - handle master key exchange from userspace
 * @skb: socket buffer
 * @info: generic netlink info
 * 
 * receives the master key from userspace during initial setup
 */
static int photon_handle_key_exchange(struct sk_buff *skb, struct genl_info *info)
{
    const u8 *master_key;
    int key_len;
    u32 portid;
    int ret;
    
    if (!info)
        return -EINVAL;
    
    portid = info->snd_portid;
    
    printk(KERN_INFO "[PHOTON RING] Key exchange request from portid %u\n", portid);

    // verify listener is registered
    ret = photon_verify_listener(portid);
    if (ret) {
        printk(KERN_ALERT "[PHOTON RING] REJECTED key exchange from unverified listener\n");
        return -EPERM;
    }

    // check if key already set (only allow once)
    if (photon_has_key()) {
        printk(KERN_ALERT "[PHOTON RING] REJECTED key exchange - key already set\n");
        printk(KERN_ALERT "[PHOTON RING] Master key can only be set once!\n");
        return -EEXIST;
    }

    // extract master key from encrypted attribute
    if (!info->attrs[PHOTON_ATTR_ENCRYPTED_KEY]) {
        printk(KERN_ERR "[PHOTON RING] No master key in key exchange message\n");
        return -EINVAL;
    }

    master_key = nla_data(info->attrs[PHOTON_ATTR_ENCRYPTED_KEY]);
    key_len = nla_len(info->attrs[PHOTON_ATTR_ENCRYPTED_KEY]);

    // validate key length
    if (key_len != PHOTON_KEY_SIZE) {
        printk(KERN_ERR "[PHOTON RING] Invalid key length: %d (expected %d)\n",
               key_len, PHOTON_KEY_SIZE);
        return -EINVAL;
    }

    printk(KERN_INFO "[PHOTON RING] Received %d-byte master key\n", key_len);

    // set the master key (derives initial session key)
    ret = photon_set_encryption_key(master_key);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] Failed to set master key: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "[PHOTON RING] ========================================\n");
    printk(KERN_INFO "[PHOTON RING] Master key established successfully!\n");
    printk(KERN_INFO "[PHOTON RING] Encryption is now ACTIVE\n");
    printk(KERN_INFO "[PHOTON RING] Events will be encrypted and sent\n");
    printk(KERN_INFO "[PHOTON RING] ========================================\n");
    
    // send immediate heartbeat to confirm encryption is working
    photon_send_heartbeat();
    
    return 0;
}

int photon_verify_listener(u32 portid)
{
    int ret;
    int i;
    unsigned long flags;
    bool found = false;

    pid_t pid = (pid_t)portid;

    // check if listener is in registered list
    spin_lock_irqsave(&listeners_lock, flags);
    for (i = 0; i < g_num_listeners; i++) {
        if (g_listeners[i].portid == portid && g_listeners[i].verified) {
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&listeners_lock, flags);

    if (found) {
        return 0; // already verified and registered
    }

    printk(KERN_WARNING "[PHOTON RING] WARNING: Listener not registered via REGISTER command\n");

    return -EPERM;
}

int photon_send_encrypted_event(struct photon_event *event)
{
    struct sk_buff *skb;
    void *msg_head;
    struct photon_encrypted_msg *enc_msg;
    size_t enc_msg_size;
    u64 rotation_num;
    int ret;

    // get current rotation number
    rotation_num = photon_get_rotation_number();

    // calculate encrypted message size
    enc_msg_size = sizeof(struct photon_encrypted_msg) + sizeof(struct photon_event);

    // allocate netlink message
    skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!skb) {
        printk(KERN_ERR "[PHOTON RING] Failed to allocate netlink message\n");
        return -ENOMEM;
    }

    // create generic netlink message header
    msg_head = genlmsg_put(skb, 0, 0, &photon_genl_family, 0, PHOTON_CMD_EVENT);
    if (!msg_head) {
        ret = -ENOMEM;
        goto nla_put_failure;
    }

    // allocate encrypted message structure
    enc_msg = kmalloc(enc_msg_size, GFP_KERNEL);
    if (!enc_msg) {
        ret = -ENOMEM;
        goto nla_put_failure;
    }

    // set rotation number
    enc_msg->rotation_num = rotation_num;

    // encrypt the event
    ret = photon_encrypt_event(event, enc_msg);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] Failed to encrypt event: %d\n", ret);
        kfree(enc_msg);
        goto nla_put_failure;
    }

    // add attributes to netlink message
    ret = nla_put_u64_64bit(skb, PHOTON_ATTR_SEQUENCE, 
                           enc_msg->sequence_num, PHOTON_ATTR_UNSPEC);
    if (ret)
        goto nla_put_failure_free;
    
    ret = nla_put_u64_64bit(skb, PHOTON_ATTR_ROTATION_NUM,
                           enc_msg->rotation_num, PHOTON_ATTR_UNSPEC);
    if (ret)
        goto nla_put_failure_free;
    
    ret = nla_put(skb, PHOTON_ATTR_IV, sizeof(enc_msg->iv), enc_msg->iv);
    if (ret)
        goto nla_put_failure_free;
    
    ret = nla_put(skb, PHOTON_ATTR_AUTH_TAG, sizeof(enc_msg->auth_tag), 
                 enc_msg->auth_tag);
    if (ret)
        goto nla_put_failure_free;
    
    ret = nla_put(skb, PHOTON_ATTR_ENCRYPTED_DATA, enc_msg->encrypted_len, 
                 enc_msg->encrypted_data);
    if (ret)
        goto nla_put_failure_free;

    // finalize message
    genlmsg_end(skb, msg_head);

    // send via multicast to all listeners
    ret = genlmsg_multicast(&photon_genl_family, skb, 0, 0, GFP_KERNEL);
    if (ret && ret != -ESRCH) {  // -ESRCH means no listeners, not an error
        printk(KERN_WARNING "[PHOTON RING] Failed to multicast message: %d\n", ret);
    }

    // clear sensitive data
    memzero_explicit(enc_msg, enc_msg_size);
    kfree(enc_msg);

    return (ret == -ESRCH) ? 0 : ret; // treat no listeners as success

nla_put_failure_free:
    memzero_explicit(enc_msg, enc_msg_size);
    kfree(enc_msg);

nla_put_failure:
    nlmsg_free(skb);
    return ret;
}

int netlink_channel_init(void)
{
    int ret;
    
    printk(KERN_INFO "[PHOTON RING] Initializing netlink channel...\n");
    
    // register generic netlink family
    ret = genl_register_family(&photon_genl_family);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] Failed to register genl family: %d\n", ret);
        return ret;
    }
    
    printk(KERN_INFO "[PHOTON RING] Generic netlink family '%s' registered\n",
           PHOTON_RING_GENL_NAME);
    printk(KERN_INFO "[PHOTON RING] Multicast group '%s' available\n",
           PHOTON_RING_MCGRP_NAME);
    
    return 0;
}

void netlink_channel_exit(void)
{
    unsigned long flags;
    
    printk(KERN_INFO "[PHOTON RING] Shutting down netlink channel...\n");
    
    // clear listener list
    spin_lock_irqsave(&listeners_lock, flags);
    printk(KERN_INFO "[PHOTON RING] Clearing %d registered listener(s)\n", g_num_listeners);
    memset(g_listeners, 0, sizeof(g_listeners));
    g_num_listeners = 0;
    spin_unlock_irqrestore(&listeners_lock, flags);
    
    // unregister generic netlink family
    genl_unregister_family(&photon_genl_family);
    
    printk(KERN_INFO "[PHOTON RING] Netlink channel shut down\n");
}