//
//  main.c
//  screen_test
//
//  Created by mike on 3/10/18.
//  Copyright © 2018 mike. All rights reserved.
//

#include <stdio.h>
#include <bootstrap.h>
#include <mach/mach.h>
#include <mach/mach_traps.h>
#include <CoreGraphics/CGDirectDisplay.h>
#include <ImageIO/CGImageDestination.h>
#include <CoreFoundation/CFURL.h>

void doCGCapture() {
    CGDirectDisplayID displays[256];
    uint32_t dispCount = 0;
    
    if(CGGetActiveDisplayList(256, displays, &dispCount)) {
        printf("Error getting display list\n");
        return;
    }
    
    for(int i = 0; i < dispCount; i++) {
        CGDirectDisplayID dispId = displays[i];
        CGImageRef img = CGDisplayCreateImage(dispId);
        
        if(img == NULL) {
            printf("unable to capture on display: %d:%08X\n", i, img);
        }
        
        char path_str[1024];
        snprintf(path_str, 1023, "./image%d.png", i);
        
        CFURLRef path = CFURLCreateWithFileSystemPath(NULL, __CFStringMakeConstantString(path_str), kCFURLPOSIXPathStyle, false);
        CGImageDestinationRef destination = CGImageDestinationCreateWithURL(path, CFSTR("public.png"), 1, NULL);
        
        if(destination == NULL) {
            printf("failed to create destination\n");
            return;
        }
        
        CGImageDestinationAddImage(destination, img, nil);
        
        if (!CGImageDestinationFinalize(destination)) {
            printf("Failed to finalize\n");
        }
        
        CFRelease(destination);
    }
}

#define WORD (4)
#define WORDS_PER_COL (2)
#define COLS_PER_LINE (2)
#define LINE_BYTES (WORD * WORDS_PER_COL * COLS_PER_LINE)
#define HEX_LEN (((WORD * 2 + 3) * WORDS_PER_COL + 2) * COLS_PER_LINE + 3)

inline static int buffers_equal(uint8_t* buf1, uint8_t* buf2, int len) {
    for (int i = 0; i < len; ++i) {
        if(buf1[i] != buf2[i]) {
            return 0;
        }
    }
    
    return 1;
}

inline static void print_buffer(uint8_t* buf, int len) {
    int i = 0;
    int chars = 0;
    
    // print line
    for(int col = 0; col < COLS_PER_LINE && i < len; ++col) {
        
        // print column
        for(int words = 0; words < WORDS_PER_COL && i < len; ++words) {
            
            // print word
            for (int w = 0; w < WORD && i < len; ++w) {
                chars += printf("%02x", buf[i++]);
                
                if(w < (WORD - 1)) {
                    chars += printf(" ");
                }
            }
            
            if(words < (WORDS_PER_COL - 1)) {
                chars += printf("  ");
            }
        }
        
        // column separator
        if(col < (COLS_PER_LINE) - 1) {
            chars += printf(" | ");
        }
    }
    
    for(int i = 0; i < (HEX_LEN + 2 - chars); ++i) {
        printf(" ");
    }
    
    for (int c = 0; c < len; ++c) {
        uint8_t ch = buf[c];
        
        if( (ch < 0x20) || (ch > 0x7e) ){
            printf("%c", '.');
        } else {
            printf("%c", ch);
        }
        
    }
    
    printf("\n");
}

void hexDump (uint *desc, uint8_t *addr, int len) {
    // Output description if given.
    printf ("%s (%d bytes):\n", desc, len);
    
    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }
    
    // do lines
    uint8_t prevBuf[LINE_BYTES];
    uint8_t lineBuf[LINE_BYTES];
    memset(prevBuf, '\0', sizeof(prevBuf));
    
    int same_count = 0;
    int prev_size = 0;
    
    // one line at a time
    for (int start = 0; start < len;) {
        int bytes_left = len - start;
        int cur_size = (bytes_left < LINE_BYTES?bytes_left:LINE_BYTES);
        
        memcpy(lineBuf, &(addr[start]), cur_size);
        
        if(prev_size == cur_size && buffers_equal(prevBuf, lineBuf, cur_size)) {
            ++same_count;
        } else {
            if(same_count > 0) {
                printf("  * %d lines (%d bytes) *\n", same_count, same_count * LINE_BYTES);
                same_count = 0;
            }
            
            printf("  %04x  ", start);
            print_buffer(lineBuf, cur_size);
            
            // remember this line
            memcpy(prevBuf, lineBuf, cur_size);
            prev_size = cur_size;
        }
        
        start += cur_size;
    }
    
    if(same_count > 0) {
        printf("  * %d lines (%d bytes) *\n", same_count, same_count * LINE_BYTES);
        same_count = 0;
    }
}

struct  __attribute__((packed)) pixel_req_msg {
    mach_msg_header_t header;
    NDR_record_t ndr;
    double x;
    double y;
    double width;
    double height;
    int32_t display_id;
    int32_t param5; // hard coded
};

struct  __attribute__((packed)) pixel_resp_msg {
    mach_msg_header_t header;
    uint32_t dword0_1;
    uint32_t object;
    uint32_t dword3_110000;
    uint32_t dword4;
    uint32_t dword5;
    uint32_t dword6;
    uint32_t dword7;
    uint32_t dword8;
    uint32_t size;
    uint32_t dword10;
    uint32_t dword11;
    uint32_t dword12;
    uint32_t dword13;
    uint32_t dword14;
};

struct  __attribute__((packed)) session_port_resp_msg {
    mach_msg_header_t header;
    uint32_t dword0;
    uint32_t remote_port;
    uint32_t dword2;
    uint32_t dword3;
    uint32_t dword4;
    uint32_t dword5;
};

struct  __attribute__((packed)) secondary_session_port_resp_msg {
    mach_msg_header_t header;
    uint32_t dword0;
    uint32_t remote_port;
    uint32_t dword2;
    uint32_t dword3;
    uint32_t dword4;
    uint32_t dword5;
    uint32_t dword6;
    uint32_t dword7;
    uint32_t dword8;
};

struct  __attribute__((packed)) server_version_resp_msg {
    mach_msg_header_t header;
    uint32_t dword0;
    uint32_t session_port;
    uint32_t dword2;
    uint32_t dword3;
    uint32_t dword4;
    uint32_t dword5;
    uint32_t version1;
    uint32_t version2;
    uint32_t dword8;
    uint32_t dword9;
    uint32_t dword10;
};

struct  __attribute__((packed)) display_state_resp_msg {
    mach_msg_header_t header;
    uint32_t dword0;
    uint32_t object_1; // size 0x28 (0000000000002D3C _initDisplayState)
    uint32_t dword2;
    uint32_t v_110000_1;
    uint32_t object_2; // size 0x2F00
    uint32_t dword5;
    uint32_t v_110000_2;
    uint32_t object_3; // size 0x2F1C
    uint32_t dword8;
    uint32_t v_110000_3;
    uint32_t dword10;
    uint32_t dword11;
};

struct display_info {
    uint32_t displayId;
};

#define BUF_SIZE 1024

int main(int argc, const char * argv[]) {
    mach_msg_return_t ret;
    u_char buffer[BUF_SIZE];
    
    mach_port_t bs_port = 0;
    mach_port_t serv_port = 0;
    mach_port_t session_port = 0;
    mach_port_t secondary_session_port = 0;
    struct display_info displayId[256];
    uint32_t numDisplays;

    mach_port_t self_port = mach_task_self();
    task_get_bootstrap_port(self_port, &bs_port);
    
    mach_msg_header_t* session_port_req;
    
    // find the server port
    kern_return_t lookup_res = bootstrap_look_up(bs_port, "com.apple.windowserver.active", &serv_port);
    printf("Server port: 0x%08X\n", serv_port);
    
    if(lookup_res == KERN_SUCCESS) {
        // prep for get_session_port
        memset(buffer, 0, BUF_SIZE);
        session_port_req = (mach_msg_header_t*)buffer;
        session_port_req->msgh_bits = 0x00001513;
        session_port_req->msgh_size = 32767;
        session_port_req->msgh_remote_port = serv_port;
        session_port_req->msgh_local_port = mig_get_reply_port();
        session_port_req->msgh_voucher_port = 0x1203;
        session_port_req->msgh_id = 0x7152;
        
        if(!voucher_mach_msg_set(session_port_req)) {
            printf("Voucher header not changed\n");
        }
        
        hexDump("Requesting Port", session_port_req, 24);
        
        ret = mach_msg(session_port_req, 0x3, 24, 48, session_port_req->msgh_local_port, 0, 0);
        if(ret != MACH_MSG_SUCCESS) {
            printf("Error sending mach message %08X\n", ret);
            exit(3);
        }
        
        hexDump("recv mach_msg", session_port_req, 48);
        
        // check session port response for errors
        struct session_port_resp_msg* sesson_port_resp = (struct session_port_resp_msg*)buffer;
        if(sesson_port_resp->dword0 != 1 || (sesson_port_resp->dword3 & 0x0FFFF0000) != 0x110000) {
            printf("Something wrong with session port response message\n");
            exit(3);
        }
        
        printf("Session port: %08X\n", sesson_port_resp->remote_port);
        session_port = sesson_port_resp->remote_port;
    } else {
        printf("Error looking up server port, trying brute force\n");
        mach_port_t serv_port_actual = serv_port;
        
        for(serv_port = 0x0000; serv_port < 0x5000; serv_port++) {
            // prep for get_session_port
            printf("(%08X) Trying: %08X\n", serv_port_actual, serv_port);
            
            memset(buffer, 0, BUF_SIZE);
            session_port_req = (mach_msg_header_t*)buffer;
            session_port_req->msgh_bits = 0x00001513;
            session_port_req->msgh_size = 32767;
            session_port_req->msgh_remote_port = serv_port;
            session_port_req->msgh_local_port = mig_get_reply_port();
            session_port_req->msgh_voucher_port = 0x1203;
            session_port_req->msgh_id = 0x7152;
            
            if(!voucher_mach_msg_set(session_port_req)) {
                printf("Voucher header not changed\n");
            }
            
            //hexDump("Requesting Port", session_port_req, 24);
            
            // setting timeouts for scanning efficiency.
            ret = mach_msg(session_port_req, 0x3 | MACH_SEND_TIMEOUT | MACH_RCV_TIMEOUT, 24, 48, session_port_req->msgh_local_port, 1000, 0);
            if(ret != MACH_MSG_SUCCESS) {
                printf("Error sending mach message %08X\n", ret);
                continue;
            }
            
            //hexDump("recv mach_msg", session_port_req, 48);
            
            // check session port response for errors
            struct session_port_resp_msg* sesson_port_resp = (struct session_port_resp_msg*)buffer;
            if(sesson_port_resp->dword0 != 1 || (sesson_port_resp->dword3 & 0x0FFFF0000) != 0x110000) {
                printf("Something wrong with session port response message\n");
                continue;
            }
            
            printf("Session port: %08X\n", sesson_port_resp->remote_port);
            session_port = sesson_port_resp->remote_port;
            break;
        }
    }
    
    
    
#if 1
    { // get display state
        memset(buffer, 0, BUF_SIZE);
        mach_msg_header_t* display_state_req = (mach_msg_header_t*)buffer;
        display_state_req->msgh_bits = 0x00001513;
        display_state_req->msgh_size = 0;
        display_state_req->msgh_remote_port = session_port;
        display_state_req->msgh_local_port = mig_get_reply_port();
        display_state_req->msgh_voucher_port = 0;
        display_state_req->msgh_id = 0x7475;
        
        if(!voucher_mach_msg_set(display_state_req)) {
            printf("Voucher header not changed\n");
        }
        
        hexDump("Requesting display state", display_state_req, 24);
        
        ret = mach_msg(display_state_req, 0x3, 24, 72, display_state_req->msgh_local_port, 0, 0);
        if(ret != MACH_MSG_SUCCESS) {
            printf("Error sending mach message %08X\n", ret);
            exit(3);
        }
        
        hexDump("recv display state", display_state_req, 72);
        
        // retrieve the data from object
        struct display_state_resp_msg* display_state_resp = (struct display_state_resp_msg*)display_state_req;
        printf("display state objects: %08X, %08X, %08X\n", display_state_resp->object_1, display_state_resp->object_2, display_state_resp->object_3);
        
        // objects
        uint8_t obj_buff[1024];
        uint8_t* ptr_obj_buff = obj_buff;
        
        // 1
        ret = mach_vm_map(mach_task_self(), &ptr_obj_buff, 0x28, 0, 0x1, display_state_resp->object_1, 0, 0, 3, 3, 1);
        if(ret != 0) {
            printf("Error allocating shared object %d\n", ret);
            //exit(3);
        } else {
            hexDump("display state object 1", ptr_obj_buff, 0x28);
            
            FILE* file = fopen("state.1", "wb");
            size_t wrote = fwrite(ptr_obj_buff, 1, 0x28, file);
            printf("Written bytes: %d\n", wrote);
            fclose(file);
        }
        
        // 2
        ret = mach_vm_map(mach_task_self(), &ptr_obj_buff, 0x2F00, 0, 0x1, display_state_resp->object_2, 0, 0, 1, 1, 1);
        if(ret != 0) {
            printf("Error allocating shared object %d\n", ret);
            //exit(3);
        } else {
            hexDump("display state object 2", ptr_obj_buff, 0x2F00);
            
            FILE* file = fopen("state.2", "wb");
            size_t wrote = fwrite(ptr_obj_buff, 1, 0x2F00, file);
            printf("Written bytes: %d\n", wrote);
            fclose(file);
        }
        
        // 3
        ret = mach_vm_map(mach_task_self(), &ptr_obj_buff, 0x2F1C, 0, 0x1, display_state_resp->object_3, 0, 0, 1, 1, 1);
        if(ret != 0) {
            printf("Error allocating shared object %d\n", ret);
            //exit(3);
        } else {
            hexDump("display state object 3", ptr_obj_buff, 0x2F1C);
            
            FILE* file = fopen("state.3", "wb");
            size_t wrote = fwrite(ptr_obj_buff, 1, 0x2F1C, file);
            printf("Written bytes: %d\n", wrote);
            fclose(file);
        }
        
        // set display info
        displayId[0].displayId = 0xFFFF0F0F;
        numDisplays = 1;
    }
#endif
    
    // default test ID's
    displayId[0].displayId = 0xFFFF0F0F;
    numDisplays = 1;
    
    { // test connection, get version
        memset(buffer, 0, BUF_SIZE);
        mach_msg_header_t* get_version_req = (mach_msg_header_t*)buffer;
        get_version_req->msgh_bits = 0x00001513;
        get_version_req->msgh_size = 0;
        get_version_req->msgh_remote_port = session_port;
        get_version_req->msgh_local_port = mig_get_reply_port();
        get_version_req->msgh_voucher_port = 0;
        get_version_req->msgh_id = 0x7148;
        
        if(!voucher_mach_msg_set(get_version_req)) {
            printf("Voucher header not changed\n");
        }
        
        hexDump("Requesting Version", get_version_req, 24);
        
        ret = mach_msg(session_port_req, 0x3, 24, 68, get_version_req->msgh_local_port, 0, 0);
        if(ret != MACH_MSG_SUCCESS) {
            printf("Error sending mach message %08X\n", ret);
            exit(3);
        }
        
        hexDump("recv mach_msg", get_version_req, 68);
        
        // check for errors for version test
        struct server_version_resp_msg* server_version_resp = (struct server_version_resp_msg*)buffer;
        if(server_version_resp->dword0 != 1 || (server_version_resp->dword3 & 0x0FFFF0000) != 0x110000) {
            printf("Something wrong with session port response message\n");
            exit(3);
        }
        
        printf("Server version: %d.%d\n", server_version_resp->version1, server_version_resp->version2);
    }
    
    // create secondary connection
    memset(buffer, 0, BUF_SIZE);
    mach_msg_header_t* second_session_req = (mach_msg_header_t*)buffer;
    second_session_req->msgh_bits = 0x80001513;
    second_session_req->msgh_size = 0;
    second_session_req->msgh_remote_port = session_port;
    second_session_req->msgh_local_port = mig_get_reply_port();
    second_session_req->msgh_voucher_port = 0;
    second_session_req->msgh_id = 0x7468;
    
    uint32_t* second_session_req_params = (uint32_t*)(buffer + sizeof(mach_msg_header_t));
    second_session_req_params[0] = 0x1;
    second_session_req_params[1] = 0x0; // allocated 03 19 00 00? some port
    second_session_req_params[2] = 0x0;
    second_session_req_params[3] = 0x00140000;
    second_session_req_params[4] = 0x0;
    second_session_req_params[5] = 0x1;
    second_session_req_params[6] = 0x0; // 25 a8 a5 73?
    second_session_req_params[7] = 0x1;
    second_session_req_params[8] = 0x0;
    second_session_req_params[9] = 0x0;
    second_session_req_params[10] = 0x0;
    second_session_req_params[11] = 0x0;
    
    if(!voucher_mach_msg_set(second_session_req)) {
        printf("Voucher header not changed\n");
    }
    
    hexDump("Requesting secondary Port", second_session_req, 72);
    
    ret = mach_msg(session_port_req, 0x3, 72, 60, second_session_req->msgh_local_port, 0, 0);
    if(ret != MACH_MSG_SUCCESS) {
        printf("Error sending mach message %08X\n", ret);
        exit(3);
    }
    
    hexDump("recv mach_msg", second_session_req, 60);
    
    struct secondary_session_port_resp_msg* secondary_session_port_resp = (struct secondary_session_port_resp_msg*)buffer;
    secondary_session_port = secondary_session_port_resp->remote_port;
    
    printf("Secondary port: %08X\n", secondary_session_port);
    
    
    for(uint32_t disp = 0; disp < numDisplays; ++disp){ // request the actual screen pixels
        struct pixel_req_msg* rq_msg = (struct pixel_req_msg*)buffer;
        
        rq_msg->header.msgh_bits = 0x1513;
        rq_msg->header.msgh_size = 0;
        rq_msg->header.msgh_remote_port = secondary_session_port;
        rq_msg->header.msgh_local_port = mig_get_reply_port();
        rq_msg->header.msgh_voucher_port = 0;
        rq_msg->header.msgh_id = 0x732A;
        
        // NDR Record value:
        rq_msg->ndr.int_rep = 1;
        
        // x, y, width, height
        rq_msg->x = 0.0;
        rq_msg->y = 0.0;
        rq_msg->width = 1024.0*3;
        rq_msg->height = 768.0*3;
        
        // display id values (vm: 0x5b81c5c0, non-vm: 0x042499b0)
        rq_msg->display_id = displayId[disp].displayId;
        rq_msg->param5 = 0x00000441;
        
        // set the voucher
        if(!voucher_mach_msg_set(&rq_msg->header)) {
            printf("Voucher header not changed\n");
        }
        
        hexDump("request pixels", rq_msg, 0x48);
        
        if(mach_msg(&rq_msg->header, 0x3, 0x48, 0x88, rq_msg->header.msgh_local_port, 0, 0) != MACH_MSG_SUCCESS) {
            printf("Error sending mach message\n");
            exit(3);
        }

        hexDump("recv pixels", rq_msg, 0x88);
        
        // Allocate pixels:
        //  kern_return_t mach_vm_map(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t size,
        //                            mach_vm_offset_t mask, int flags, mem_entry_name_port_t object,
        //                            memory_object_offset_t offset, boolean_t copy, vm_prot_t cur_protection,
        //                            vm_prot_t max_protection, vm_inherit_t inheritance);
        struct pixel_resp_msg* pixel_resp = (struct pixel_resp_msg*)rq_msg;
        
        printf("Object %8X\nSize: %d\n", pixel_resp->object, pixel_resp->size);
        
        uint32_t* img_buf = (uint32_t*)buffer;
        ret = mach_vm_map(mach_task_self(), &img_buf, pixel_resp->size, 0, 0x1, pixel_resp->object, 0, 0, 3, 3, 1);
        if(ret != 0) {
            printf("Error allocating shared pixels %d\n", ret);
            exit(3);
        }
        
        FILE* file = fopen("image.raw", "wb");
        size_t wrote = fwrite(img_buf, 1, pixel_resp->size, file);
        printf("Written bytes: %d\n", wrote);
        fclose(file);
    }
    
    return 0;
}
