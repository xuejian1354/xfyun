#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <switch.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>         
#include <strings.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "qisr.h"
#include "msp_cmn.h"
#include "msp_errors.h"


#define KeyWord_PleaseDial    "请拨打"
#define KeyWord_HandOff       "请挂机"

enum KACTION
{
	Action_PleaseDial,
	Action_HandOff
	
};

#define	BUFFER_SIZE	4096
#define FRAME_LEN	640 
#define HINTS_SIZE  100
enum sr_audsrc
{
	SR_MIC,	/* write data from mic */
	SR_USER	/* write data from user by calling API */
};
enum {
	SR_STATE_INIT,
	SR_STATE_STARTED
};

#define SR_MALLOC malloc
#define SR_MFREE  free
#define SR_MEMSET	memset
#define sr_dbg printf

#define E_SR_NOACTIVEDEVICE		1
#define E_SR_NOMEM				2
#define E_SR_INVAL				3
#define E_SR_RECORDFAIL			4
#define E_SR_ALREADY			5


static char recogcmd[64] = "xbinfo ==>";


struct speech_rec_notifier {
	void (*on_result)(void *sr, const char *result, char is_last);
	void (*on_speech_begin)();
	void (*on_speech_end)(int reason);	/* 0 if VAD.  others, error : see E_SR_xxx and msp_errors.h  */
};

#define END_REASON_VAD_DETECT	0	/* detected speech done  */

typedef struct {

    enum sr_audsrc aud_src;  
	struct speech_rec_notifier notif;
	const char * session_id;
	int ep_stat;
	int rec_stat;
	int audio_status;
	struct recorder *recorder;
	volatile int state;
	char * session_begin_params;

    switch_core_session_t   *session;
    switch_media_bug_t      *bug;
    char                    *id;
    char                    *seceret;

    int                     action;
switch_memory_pool_t *pool;
	char dialdata[256];
} speech_rec;
void sr_uninit(speech_rec * sr);
int sr_init_ex(speech_rec * sr, const char * session_begin_params, 
			enum sr_audsrc aud_src, int devid, 
				struct speech_rec_notifier * notify);
				
//系统启动时或运行时加载模块，模块的全局数据结构，钩子设置
SWITCH_MODULE_LOAD_FUNCTION(mod_speechreg_load);
//系统运行时loop, 这里可以启动线程处理请求，监听socket 等等
SWITCH_MODULE_RUNTIME_FUNCTION(mod_speechreg_runtime); 
//模块卸载，这里负责清除全局数据结构，释放资源
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_speechreg_shutdown);
//模块的定义
SWITCH_MODULE_DEFINITION(mod_speechreg, mod_speechreg_load, mod_speechreg_shutdown, NULL);
static void Sleep(size_t ms)
{
	usleep(ms*1000);
}
static void end_sr_on_error(speech_rec *sr, int errcode)
{
	
	if (sr->session_id) {
		if (sr->notif.on_speech_end)
			sr->notif.on_speech_end(errcode);

		QISRSessionEnd(sr->session_id, "err");
		sr->session_id = NULL;
	}
	sr->state = SR_STATE_INIT;
}
static void end_sr_on_vad(speech_rec *sr)
{
	int errcode;
	const char *rslt;
	while(sr->rec_stat != MSP_REC_STATUS_COMPLETE ){
		rslt = QISRGetResult(sr->session_id, &sr->rec_stat, 0, &errcode);
		if (rslt && sr->notif.on_result)
			sr->notif.on_result(sr, rslt, sr->rec_stat == MSP_REC_STATUS_COMPLETE ? 1 : 0);
			Sleep(100); 
	}

	if (sr->session_id) {
		if (sr->notif.on_speech_end)
			sr->notif.on_speech_end(END_REASON_VAD_DETECT);
		QISRSessionEnd(sr->session_id, "VAD Normal");
		sr->session_id = NULL;
	}
	sr->state = SR_STATE_INIT;
}

int sr_init(speech_rec * sr, const char * session_begin_params, 
		enum sr_audsrc aud_src, struct speech_rec_notifier * notify)
{
	return sr_init_ex(sr, session_begin_params, aud_src, 0, notify);
}
void sr_uninit(speech_rec * sr)
{
	
	if (sr->session_begin_params) {
		SR_MFREE(sr->session_begin_params);
		sr->session_begin_params = NULL;
	}
}
int sr_init_ex(speech_rec * sr, const char * session_begin_params, enum sr_audsrc aud_src, int devid, struct speech_rec_notifier * notify)
{
	size_t param_size;
	if (!sr)
		return -E_SR_INVAL;

//	SR_MEMSET(sr, 0, sizeof(speech_rec));
	sr->state = SR_STATE_INIT;
	sr->aud_src = aud_src;
	sr->ep_stat = MSP_EP_LOOKING_FOR_SPEECH;
	sr->rec_stat = MSP_REC_STATUS_SUCCESS;
	sr->audio_status = MSP_AUDIO_SAMPLE_FIRST;

	param_size = strlen(session_begin_params) + 1;
	sr->session_begin_params = (char*)SR_MALLOC(param_size);
	if (sr->session_begin_params == NULL) {
		sr_dbg("mem alloc failed\n");
		return -E_SR_NOMEM;
	}
	strncpy(sr->session_begin_params, session_begin_params, param_size);

	sr->notif = *notify;	

	return 0;
}

int sr_start_listening(speech_rec *sr)
{
	const char *session_id = NULL;
	int	errcode = MSP_SUCCESS;

	if (sr->state >= SR_STATE_STARTED) {
		//sr_dbg("already STARTED.\n");
		return -E_SR_ALREADY;
	}

	session_id = QISRSessionBegin(NULL, sr->session_begin_params, &errcode); 
	if (MSP_SUCCESS != errcode)
	{
		//sr_dbg("\nQISRSessionBegin failed! error code:%d\n", errcode);
		return errcode;
	}
	sr->session_id = session_id;
	sr->ep_stat = MSP_EP_LOOKING_FOR_SPEECH;
	sr->rec_stat = MSP_REC_STATUS_SUCCESS;
	sr->audio_status = MSP_AUDIO_SAMPLE_FIRST;

	sr->state = SR_STATE_STARTED;

	if (sr->notif.on_speech_begin)
		sr->notif.on_speech_begin();

	return 0;
}

int sr_stop_listening(speech_rec *sr)
{
	int ret = 0;
	const char * rslt = NULL;

	if (sr->state < SR_STATE_STARTED) {
		//sr_dbg("Not started or already stopped.\n");
		return 0;
	}
	sr->state = SR_STATE_INIT;
	ret = QISRAudioWrite(sr->session_id, NULL, 0, MSP_AUDIO_SAMPLE_LAST, &sr->ep_stat, &sr->rec_stat);
	if (ret != 0) {
		//sr_dbg("write LAST_SAMPLE failed: %d\n", ret);
		QISRSessionEnd(sr->session_id, "write err");
		return ret;
	}
	while (sr->rec_stat != MSP_REC_STATUS_COMPLETE) {
		rslt = QISRGetResult(sr->session_id, &sr->rec_stat, 0, &ret);
		if (MSP_SUCCESS != ret)	{
			//sr_dbg("\nQISRGetResult failed! error code: %d\n", ret);
			end_sr_on_error(sr, ret);
			return ret;
		}
		if (NULL != rslt && sr->notif.on_result)
			sr->notif.on_result(sr, rslt, sr->rec_stat == MSP_REC_STATUS_COMPLETE ? 1 : 0);
		Sleep(100);
	}

	QISRSessionEnd(sr->session_id, "normal");
	sr->session_id = NULL;
	return 0;
}
int sr_write_audio_data(speech_rec *sr, char *data, unsigned int len)
{
	const char *rslt = NULL;
	int ret = 0;
	if (!sr )
		return -E_SR_INVAL;
	if (!data || !len)
		return 0;

	ret = QISRAudioWrite(sr->session_id, data, len, sr->audio_status, &sr->ep_stat, &sr->rec_stat);
	if (ret) {
		end_sr_on_error(sr, ret);
		return ret;
	}
	sr->audio_status = MSP_AUDIO_SAMPLE_CONTINUE;

	if (MSP_REC_STATUS_SUCCESS == sr->rec_stat) { 
		rslt = QISRGetResult(sr->session_id, &sr->rec_stat, 0, &ret);
		if (MSP_SUCCESS != ret)	{
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "\nQISRGetResult failed! error code: %d\n", ret);
			end_sr_on_error(sr, ret);
			return ret;
		}
		if (NULL != rslt && sr->notif.on_result)
			sr->notif.on_result(sr, rslt, sr->rec_stat == MSP_REC_STATUS_COMPLETE ? 1 : 0);
	}
	if (MSP_EP_AFTER_SPEECH == sr->ep_stat) {
		end_sr_on_vad(sr);
	}
	return 0;
}
void parse_phonenum(const char* instr, char* outnum) 
{
	const char* p = instr;
	char* s = outnum;
	while(*p) {
		if (*p >= '0' && *p <= '9') {
			*s = *p;
			s++;
			p++;
		}
		else {
			break;
		}
	}
	*s = 0;
}

void on_result(void *sr1, const char *result, char is_last)
{
	if (!result) return;

	speech_rec * sr = (speech_rec*)sr1;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "you said:%s\n", result);


	int action = -1;
	int offset=0;
	char phonenum[24]={0};
	if (action == -1 && strncmp(result, KeyWord_PleaseDial, strlen(KeyWord_PleaseDial)) == 0) {
		action = Action_PleaseDial;
		offset = strlen(KeyWord_PleaseDial);
		bzero(recogcmd, sizeof(recogcmd));
		strcpy(recogcmd, result);
	}
	if (action == -1 && strncmp(result, KeyWord_HandOff, strlen(KeyWord_HandOff)) == 0) {
		action = Action_HandOff;
		offset = strlen(KeyWord_HandOff);
	}
	if (action == -1) return;
	switch(action) {
		case Action_PleaseDial:
		{
			parse_phonenum(&result[offset], phonenum);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "auto dial user:%s\n", phonenum);			
			sr->action = action;
		}
		break;
		case Action_HandOff:
		{
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "start handoff\n");
			sr->action = action;
		}
		break;
		default:
		return;
	}
}
static void *SWITCH_THREAD_FUNC sms_thread(switch_thread_t *thread, void *obj)
{
	speech_rec * sr = (speech_rec*)obj;
	switch_event_t *event;
	switch_channel_t *caller_channel = switch_core_session_get_channel(sr->session);
	const char* result = switch_channel_get_variable(caller_channel,"sip_contact_uri");
	if (switch_event_create_subclass(&event,SWITCH_EVENT_CUSTOM,"SMS::SEND_MESSAGE") == SWITCH_STATUS_SUCCESS)
	{
	    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "%s|%s\n","2222222222222222222222222222222222",result);
	    switch_event_add_header(event, SWITCH_STACK_BOTTOM,"proto", "sip");
	    switch_event_add_header(event, SWITCH_STACK_BOTTOM,"dest_proto", "sip");
	    switch_event_add_header(event, SWITCH_STACK_BOTTOM,"from", "888@192.168.0.163");
	    switch_event_add_header(event, SWITCH_STACK_BOTTOM,"from_full", "sip:888@192.168.0.163");
	    switch_event_add_header(event, SWITCH_STACK_BOTTOM,"to", result);
	    switch_event_add_header(event, SWITCH_STACK_BOTTOM,"subject", result);
	    switch_event_add_header(event, SWITCH_STACK_BOTTOM,"type", "text/plain");
	    switch_event_add_header(event, SWITCH_STACK_BOTTOM,"sip_profile", "internal");
	    switch_event_add_body(event, "%s", recogcmd);
	    switch_event_fire(&event);
	}
	return NULL;
}
static switch_bool_t mediadata_callback(switch_media_bug_t *bug, void *user_data, switch_abc_type_t type)
{
	speech_rec *sr = (speech_rec *)user_data;
    switch_channel_t *channel = switch_core_session_get_channel(sr->session);
	int	errcode = 0;
    switch (type) 
	{
		case SWITCH_ABC_TYPE_INIT:
			{
				errcode = sr_start_listening(sr);
				if (errcode) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "ASR Start Failed channel:%s\n", switch_channel_get_name(channel));
					return SWITCH_FALSE;
				}else {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "ASR Start Succeed channel:%s\n", switch_channel_get_name(channel));
				}
			}
			break;
		case SWITCH_ABC_TYPE_CLOSE:
			{        
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "ASR Stop Succeed channel:%s\n", 	switch_channel_get_name(channel));
				sr_stop_listening(sr);
				sr_uninit(sr);
				MSPLogout();
				switch_call_cause_t cause = SWITCH_CAUSE_NORMAL_CLEARING;
				switch_channel_hangup(switch_core_session_get_channel(sr->session), cause);
				return SWITCH_FALSE;
			}
			break;
		case SWITCH_ABC_TYPE_READ_REPLACE:
			{
				switch_frame_t *frame;
				if ((frame = switch_core_media_bug_get_read_replace_frame(bug))) {
					char*frame_data = (char*)frame->data;
					int frame_len = frame->datalen;
					switch_core_media_bug_set_read_replace_frame(bug, frame);
					if (frame->channels != 1)
					{
						switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "nonsupport channels:%d!\n",frame->channels);
						return SWITCH_FALSE;
					}
					if (sr->action==Action_HandOff) 
					{
						return SWITCH_FALSE;
					}else if (sr->action==Action_PleaseDial) {
						sr->action = -1;
						switch_thread_t *thread;
						switch_threadattr_t *thd_attr = NULL;
						switch_memory_pool_t *pool;
						switch_core_new_memory_pool(&pool);
						sr->pool = pool;
						switch_threadattr_create(&thd_attr, sr->pool);
						switch_threadattr_detach_set(thd_attr, 1);
						switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
						switch_thread_create(&thread, thd_attr, sms_thread, sr, sr->pool);
					}					  
					errcode = sr_write_audio_data(sr, frame_data, frame_len);
					if (errcode != 0) {
						if (errcode == 10108) {
							errcode = sr_start_listening(sr);
							if (errcode) {
								switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "ASR Start Again Failed channel:%s\n", switch_channel_get_name(channel));
								return SWITCH_FALSE;
							}
						}          	
					}
				}
			}
        break;
		default: break;
	}
	return SWITCH_TRUE;
}

SWITCH_STANDARD_APP(start_speechreg)
{
	int	ret	= MSP_SUCCESS;
	// 登录参数，appid与msc库绑定
	const char* login_params = "appid = 5cdd1c7d, work_dir = .";

	const char* session_begin_params =
		"sub = iat, domain = iat, language = zh_cn, "
		"accent = mandarin, sample_rate = 16000, "
		"result_type = plain, result_encoding = utf8";

    switch_channel_t *channel = switch_core_session_get_channel(session);
	
	switch_status_t status;
    speech_rec *sr;
	switch_codec_implementation_t read_impl;
	//初始化 read_impl内存
    memset(&read_impl, 0, sizeof(switch_codec_implementation_t));
	char *argv[2] = { 0 };
    int argc;
    char *lbuf = NULL;
	//zstr函数用于判断空字符串
	if (!zstr(data) && (lbuf = switch_core_session_strdup(session, data))&& (argc = switch_separate_string(lbuf, ' ', argv, (sizeof(argv) / sizeof(argv[0])))) >= 2) {
		switch_core_session_get_read_impl(session, &read_impl);	
		if (!(sr = (speech_rec*)switch_core_session_alloc(session, sizeof(speech_rec)))) {
            return;
        }
		
		SR_MEMSET(sr, 0, sizeof(speech_rec));
        sr->action = -1;
        sr->session = session;
        sr->id = argv[0];
        sr->seceret = argv[1];
		
		//语音服务登录
		ret = MSPLogin(NULL, NULL, login_params); 
		if (MSP_SUCCESS != ret)
		{
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "MSPLogin failed , Error code %d.\n",ret);
			return;//登录失败，退出登录
		}
		int	errcode = 0;	
		struct speech_rec_notifier recnotifier = {
			on_result
		};

		errcode = sr_init(sr, session_begin_params, SR_USER, &recnotifier);
		if (errcode) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "speech recognizer init failed : %d\n", errcode);
			return;
		}
		if ((status = switch_core_media_bug_add(session, "speechreg", NULL,mediadata_callback, sr, 0, SMBF_READ_REPLACE | SMBF_NO_PAUSE | SMBF_ONE_ONLY, &(sr->bug))) != SWITCH_STATUS_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "bug add failed.\n");
            return;
        }
		switch_channel_set_private(channel, "speechreg", sr);
	}else {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "%s id or secret can not be empty\n", switch_channel_get_name(channel));
    }
}

SWITCH_STANDARD_APP(stop_speechreg)
{
	speech_rec *sr;
    switch_channel_t *channel = switch_core_session_get_channel(session);

    if ((sr = (speech_rec*)switch_channel_get_private(channel, "speechreg"))) {

        switch_channel_set_private(channel, "speechreg", NULL);
        switch_core_media_bug_remove(session, &sr->bug);
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "%s Stop ASR\n", switch_channel_get_name(channel));

    }
}
SWITCH_MODULE_LOAD_FUNCTION(mod_speechreg_load)
{
	//申明一个变量
	switch_application_interface_t *app_interface;
  
    *module_interface = switch_loadable_module_create_module_interface(pool, modname);

	//向核心注册APP并设置一个回调SWITCH_STANDARD_APP
    SWITCH_ADD_APP(app_interface, "start_speechreg", "speechreg", "speechreg",start_speechreg, "", SAF_MEDIA_TAP);
    SWITCH_ADD_APP(app_interface, "stop_speechreg", "speechreg", "speechreg", stop_speechreg, "", SAF_NONE);

    return SWITCH_STATUS_SUCCESS;
}

 SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_speechreg_shutdown)
{
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, " mod_speechreg_shutdown\n");

    return SWITCH_STATUS_SUCCESS;
}
