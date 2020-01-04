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

int main(void)
{
    uint8_t v1 = 1;
    uint8_t v2 = 2;
    uint8_t v3 = 3;

    Packet* hdr = NULL;
    Packet* pkt1 = (Packet*)malloc(sizeof(Packet));
    pkt1->buf = &v1;
    pkt1->next = NULL;
    Packet* pkt2 = (Packet*)malloc(sizeof(Packet));
    pkt2->buf = &v2;
    pkt2->next = NULL;
    Packet* pkt3 = (Packet*)malloc(sizeof(Packet));
    pkt3->buf = &v3;
    que_append(&hdr, pkt1);
    que_print(hdr);
    que_append(&hdr, pkt2);
    que_print(hdr);
    que_append(&hdr, pkt3);
    que_print(hdr);
    que_pop(&hdr);
    que_print(hdr);

//    Node* hdr = NULL;
//    append(&hdr, 3);
//    print(hdr);
//    append(&hdr, 4);
//    print(hdr);

    return 0;
}
