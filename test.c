#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct packet_t {
    uint8_t* buf;           /* A raw Ethernet frame, presumably with the dest MAC empty */
    unsigned int len;           /* Length of raw Ethernet frame */
    struct packet_t* next;
} Packet;

void que_append(Packet** hdr_ptr, Packet* packet)
{
    if (*hdr_ptr == NULL){
        *hdr_ptr = packet;
    }
    else {
        for (Packet* t = *hdr_ptr; t != NULL; t = t->next){
            if (t->next == NULL){
                t->next = packet;
                break;
            }
        }
    }
}

Packet* que_pop(Packet** hdr_ptr)
{
    if (*hdr_ptr == NULL){
        return NULL;
    }
    else {
        Packet* ret = *hdr_ptr;
        *hdr_ptr = ret->next;
        ret->next = NULL;
        return ret;
    }
}

void que_print(Packet* hdr)
{
    int cnt = 0;
    for (Packet* t = hdr; t != NULL; t = t->next){
        cnt += 1;
        printf("%d, ", *(t->buf));
    }
    printf("size = %d\n", cnt);
}

typedef struct node_t
{
    int val;
    struct node_t* next;
}Node;

void append(Node** hdr_ptr, int d)
{
    Node* node = (Node*)malloc(sizeof(Node));
    node->val = d;
    node->next = NULL;

    if (*hdr_ptr == NULL){
        *hdr_ptr = node;
    }
    else {
        Node* hdr = *hdr_ptr;
        for (Node* t = *hdr_ptr; t != NULL; t = t->next){
            if (t->next == NULL){
                t->next = node;
                break;
            }
        }
    }
}

void print(Node* hdr)
{
    printf("[");
    for (Node* t = hdr; t != NULL; t = t->next){
        printf("%d, ", t->val);
    }
    printf("]\n");
}
#define A 0x08
int main(void)
{
    printf("0x%02x\n", A);

//    Node* hdr = NULL;
//    append(&hdr, 3);
//    print(hdr);
//    append(&hdr, 4);
//    print(hdr);

    return 0;
}
