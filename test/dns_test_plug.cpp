/*
 *  author:yangwei
 *  create time:2021-8-21
 *
 */



#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>

#include "cJSON.h"
#include "dns.h"
#include "MESA_prof_load.h"
#include <MESA/stream.h>

extern "C" int commit_test_result_json(cJSON *node, const char *name);

static int g_result_count = 1;

extern "C" unsigned char DNS_TEST_PLUG_ENTRY(stSessionInfo *session_info, void **pme,
                             int thread_seq, struct streaminfo *a_stream, void *a_packet)
{
    assert(NULL != session_info || pme != NULL);

    cJSON *ctx = NULL;
    dns_info_t *dns_info=(dns_info_t *)session_info->app_info;
	assert(dns_info!=NULL && a_stream!=NULL);

    if(strlen((char *)dns_info->query_question.qname)==0)return PROT_STATE_DROPME;

    ctx = cJSON_CreateObject();
    cJSON_AddStringToObject(ctx, "Tuple4", printaddr(&a_stream->addr, thread_seq));

    cJSON_AddStringToObject(ctx, "dns_qname", (const char *)dns_info->query_question.qname);
    cJSON_AddNumberToObject(ctx, "dns_qtype", (double)dns_info->query_question.qtype);
    cJSON_AddNumberToObject(ctx, "dns_qclass", (double)dns_info->query_question.qclass);
    cJSON_AddNumberToObject(ctx, "dns_qr", (double)dns_info->hdr_info.qr);
    cJSON_AddNumberToObject(ctx, "dns_opcode", (double)dns_info->hdr_info.opcode);
    cJSON_AddNumberToObject(ctx, "dns_rd", (double)dns_info->hdr_info.rd);

	int dns_sec=0;
	cJSON *rr_object=cJSON_CreateObject();
	get_rr_str2json(rr_object, dns_info, &dns_sec);
	cJSON_AddItemToObject(ctx, "rr", rr_object);

    char result_name[16] = "";
    sprintf(result_name, "DNS_RESULT_%d", g_result_count);
    commit_test_result_json(ctx, result_name);
    g_result_count += 1;

    return PROT_STATE_DROPME;
}

extern "C" int QUIC_TEST_PLUG_INIT()
{
    return 0;
}

extern "C" void QUIC_TEST_PLUG_DESTROY(void)
{
    return ;
}/*CHAR_DESTRORY*/



