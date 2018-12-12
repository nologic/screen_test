#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <execinfo.h>

#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/types.h>
#include <sys/syslog.h>
#include <sys/stat.h>

#include <pthread.h>

#include <xpc/xpc.h>

#include "pcap.h"

// Interposing LibXPC - J Levin, http://NewAndroidBook.com/
//
// Compile with gcc xpcsnoop -shared -o xpcsnoop.dylib
// 
// then shove forcefully with
//
// DYLD_INSERT_LIBRARIES=...
//
// Only the basic functionality, but the interesting one
// (i.e. snooping XPC messages!)
//
// Much more to be shown with MOXiI 2
//

//
// This is the expected interpose structure
typedef struct interpose_s { 
	void *new_func; 
	void *orig_func; 
} interpose_t;

#define MACH_TYPE_mach_msg           ((uint16_t)0)
#define MACH_TYPE_mach_msg_overwrite ((uint16_t)1)
#define MACH_TYPE_bootstrap_look_up2 ((uint16_t)3)

typedef struct __attribute__((__packed__)) mach_hdr_pcap_s {
	uint16_t mach_type;
	uint16_t backtrace_count;
	uint32_t thread_id;
	uint32_t proc_id;
	uint32_t task_id;
} mach_hdr_pcap_t;

typedef struct __attribute__((__packed__)) mach_msg_hdr_pcap_s {
	mach_msg_option_t             option;
	mach_msg_size_t            send_size;
	mach_msg_size_t        receive_limit;
	mach_port_t             receive_name;
	mach_msg_timeout_t           timeout;
	mach_port_t                   notify;
	mach_msg_size_t     receive_msg_size;
} mach_msg_hdr_pcap_t;

typedef struct __attribute__((__packed__)) mach_msg_pcap_s {
	mach_hdr_pcap_t hdr;
	mach_msg_hdr_pcap_t msg_hdr;

	// [ mach_msg_header_t           send_msg |
	//   mach_msg_header_t        receive_msg ]
	// char** 					backtrace
} mach_msg_pcap_t;

void hexDump (char *desc, void *addr, int len);
void *my_libxpc_initializer (void);

int pcap_out = NULL;
pthread_mutex_t mutex;

extern void *_libxpc_initializer(void);

static inline void do_backtrace(void) {
    static char backtraceBuf[16384];
    int num = backtrace(backtraceBuf, 16384);
    char **backtraceSyms = backtrace_symbols(backtraceBuf, num);

    if (backtraceSyms) {
	  for (int i = 0; i < num; i++) {
		fprintf(stderr, "%s\n", backtraceSyms[i]);
	  }
	}
}

int serialize_backtrace(char** bt, uint16_t num, uint8_t* buffer, int buffer_size) {
	uint8_t* b = buffer;
	uint8_t* b_end = buffer + buffer_size;

	// number of entries
	memcpy(b, &num, sizeof(num));
	b += sizeof(num);

	// write each entry
	for(int i = 0; i < num; i++) {
		uint16_t l_str = strlen(bt[i]);

		// size of entry
		memcpy(b, &l_str, sizeof(l_str));
		b += sizeof(l_str);

		// entry
		memcpy(b, bt[i], l_str);
		b += l_str;
	}

	// bytes used
	return (int)(b - buffer);
}

int write_msg_send(int out_fd, mach_msg_pcap_t* hdr_data, mach_msg_header_t* msg, int msg_size,
	                       char* backtraceBuf, int backtrace_num) {

	int acc = 0;
	
	uint8_t bt_buffer[16384];
	char **backtraceSyms;
	uint16_t bt_buffer_size;
	
	struct pcap_pkthdr pkt_header = { 0 };

	// serialize backtrace
	memset(bt_buffer, 0, sizeof(bt_buffer));
	backtraceSyms = backtrace_symbols(backtraceBuf, backtrace_num);
	bt_buffer_size = serialize_backtrace(backtraceSyms, backtrace_num, bt_buffer, sizeof(bt_buffer));

	// get current time
	gettimeofday(&pkt_header.ts, NULL);

	// set packet size
	pkt_header.caplen = pkt_header.len = sizeof(*hdr_data) + msg_size + bt_buffer_size;

	// serialize packet
	acc += write(out_fd, &pkt_jdiheader, sizeof(pkt_header));
	acc += write(out_fd, hdr_data, sizeof(*hdr_data));
	acc += write(out_fd, msg, msg_size);
	acc += write(out_fd, bt_buffer, bt_buffer_size);

	return acc;
}

void my_xpc_connection_send_message(xpc_connection_t connection, xpc_object_t message) {
	fprintf (stderr,"Message on connection %s: %s\n", xpc_copy_description(connection), xpc_copy_description(message));
	if (xpc_get_type (message) == XPC_TYPE_DICTIONARY)
	//dumpDict("XPC message", connection, 0); else { fprintf(stderr,"Message not a dictionary");}
	do_backtrace();
	xpc_connection_send_message (connection, message);

}

extern void *xpc_pipe_routine (void *xpcPipe, xpc_object_t *inDict, xpc_object_t *out);

void *my_xpc_pipe_routine (void *xpcPipe, xpc_object_t *inDict, xpc_object_t *outDict)
{
	do_backtrace();
	fprintf (stderr,"Pipe routine on pipe %p (%s)\n\tmessage  %s\n----\n", xpcPipe, xpc_copy_description(xpcPipe), xpc_copy_description(inDict));

	return(xpc_pipe_routine (xpcPipe, inDict, outDict));

}



xpc_connection_t my_xpc_connection_create(const char *name, dispatch_queue_t targetq)
{

	fprintf (stderr,"xpc_connection_create(\"%s\", targetq=%p);\n", name, targetq);
	xpc_connection_t returned = xpc_connection_create (name, targetq);
	fprintf(stderr,"Returning %p\n", returned);
	return (returned);
}

void *my_libxpc_initializer (void)
{

	fprintf(stderr,"In XPC Initializer..\n");
	return (_libxpc_initializer());
} ;

kern_return_t my_bootstrap_look_up2(mach_port_t bp, const char* service_name, mach_port_t *sp, pid_t target_pid, uint64_t flags) {
	kern_return_t ret = bootstrap_look_up2(bp, service_name, sp, target_pid, flags);
	printf("%s: 0x%X\n", service_name, *sp);
	return ret;
}

mach_msg_return_t   my_mach_msg
                    (mach_msg_header_t*               msg,
                     mach_msg_option_t             option,
                     mach_msg_size_t            send_size,
                     mach_msg_size_t        receive_limit,
                     mach_port_t             receive_name,
                     mach_msg_timeout_t           timeout,
                     mach_port_t                   notify) 
{

	// record the outgoing mesasge
	pthread_mutex_lock(&mutex);

	//do_backtrace();
	printf("msgh_bits: %X\n", msg->msgh_bits);
	printf("msgh_size: %d (%d)\n", msg->msgh_size, send_size);
	printf("ports: %X -> %X\n", msg->msgh_local_port, msg->msgh_remote_port);
	printf("msgh_reserved: %X\n", msg->msgh_reserved);
	printf("msgh_id: %X\n", msg->msgh_id);
	
	hexDump("mach_msg", ((char*)msg) + sizeof(mach_msg_header_t), send_size);
	printf("\n");

	// write pcap
	static char backtraceBuf[16384];
    int bt_num = backtrace(backtraceBuf, 16384);
	
	mach_msg_pcap_t pkt = {
		.hdr = {
			.mach_type = MACH_TYPE_mach_msg,
			.backtrace_count = bt_num,
			.thread_id = 0,
			.proc_id = getpid(),
			.task_id = 0,
		},

		.msg_hdr = {
			.option = option,
			.send_size = send_size,
			.receive_limit = receive_limit,
			.receive_name = receive_name,
			.timeout = timeout,
			.notify = notify,
		}
	};

	write_msg_send(pcap_out, &pkt, msg, send_size, backtraceBuf, bt_num);
	
	pthread_mutex_unlock(&mutex);

	// call the original function.
	mach_msg_return_t ret = mach_msg(msg, option, send_size, receive_limit, receive_name, timeout, notify);

	pthread_mutex_lock(&mutex);
	printf("msgh_bits: %X\n", msg->msgh_bits);
	printf("msgh_size: %d (%d)\n", msg->msgh_size, send_size);
	printf("ports: %X -> %X\n", msg->msgh_local_port, msg->msgh_remote_port);
	printf("msgh_reserved: %X\n", msg->msgh_reserved);
	printf("msgh_id: %X\n", msg->msgh_id);
	
	hexDump("mach_msg", ((char*)msg) + sizeof(mach_msg_header_t), receive_limit);
	printf("\n");

	pthread_mutex_unlock(&mutex);

	return ret;
}

mach_msg_return_t   my_mach_msg_overwrite
                    (mach_msg_header_t*          send_msg,
                     mach_msg_option_t             option,
                     mach_msg_size_t            send_size,
                     mach_msg_size_t        receive_limit,
                     mach_port_t             receive_name,
                     mach_msg_timeout_t           timeout,
                     mach_port_t                   notify,
                     mach_msg_header_t       *receive_msg,
                     mach_msg_size_t     receive_msg_size)
{
	mach_msg_return_t ret = mach_msg_overwrite(send_msg, option, send_size, receive_limit, receive_name, timeout, notify, receive_msg, receive_msg_size);

	return ret;
}

static const interpose_t interposing_functions[] __attribute__ ((used,section("__DATA, __interpose"))) = {

 //{ (void *) my_xpc_connection_send_message, (void *) xpc_connection_send_message },
 // { (void *) my_libxpc_initializer, (void *) _libxpc_initializer },
 //{ (void *) my_xpc_pipe_routine, (void *) xpc_pipe_routine },
 //{ (void *) my_xpc_connection_create, (void *) xpc_connection_create },
 { (void*) my_bootstrap_look_up2, (void*)bootstrap_look_up2 },
 { (void*) my_mach_msg, (void*)mach_msg },
 { (void*) my_mach_msg_overwrite, (void*)mach_msg_overwrite },
};

void xpc_connection_send_barrier(xpc_connection_t connection, dispatch_block_t barrier);
void xpc_connection_send_message_with_reply(xpc_connection_t connection, xpc_object_t message, dispatch_queue_t targetq, xpc_handler_t handler);
xpc_object_t xpc_connection_send_message_with_reply_sync(xpc_connection_t connection, xpc_object_t message);

__attribute__((constructor)) void initialize() {
	pthread_mutex_init(&mutex, NULL);

	char* output_file = getenv("MACHSHARK_OUTPUT");
	if(output_file == NULL) {
		output_file = "output.pcap";
	}

	pcap_out = open(output_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);

	struct pcap_file_header header = {
		.magic = 0xa1b2c3d4,
		.version_major = 2,
		.version_minor = 4,
		.thiszone = 0,
		.sigfigs = 0,
		.snaplen = 65535,
		.linktype = 277 //LINKTYPE_MACH
	};

	write(pcap_out, &header, sizeof(header));

	if(pcap_out == -1) {
		perror("unable to open output pcap");
		exit(1);
	}
}

__attribute__((destructor)) void deinitialize() {
     close(pcap_out);
     pthread_mutex_destroy(&mutex);

     printf("Thanks for the sniff\n");
}

void hexDump (char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;
    
    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);
    
    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }
    
    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).
        
        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);
            
            // Output the offset.
            printf ("  %04x ", i);
        } else if(i % 8 == 0){
            printf (" |");
        } else if(i % 4 == 0){
            printf (" ");
        }
        
        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);
        
        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }
    
    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }
    
    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}

