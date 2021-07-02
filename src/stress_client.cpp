#include "tcp/tcp_client.h"
#include "log/log.h"

#include "timer/timer.h"
#include "thread/task_thread_pool.h"
#include "tcp/packet.h"
#include "version.h"
#include "ini/ini.h"
#include "stdx.h"

#include <vector>
#include <mutex>
#include <signal.h>
#include <string.h>
#include <chrono>

#ifdef WIN32
#include "ioevent/iocp.h"
#else
#include <unistd.h>
#include "ioevent/io_event.h"
#endif // WIN32



struct ClienttType
{
    std::shared_ptr<stdx::tcp::TcpClient> clt_;
    std::chrono::system_clock::time_point last_tp_;
    int64_t id_;
    ClienttType(const std::shared_ptr<stdx::tcp::TcpClient>& ct,const std::chrono::system_clock::time_point& tp)
    :clt_(ct),last_tp_(tp),id_(0)
    {
             
    }
};


std::vector<std::shared_ptr<ClienttType>> v;

std::mutex mtx;

std::atomic<int64_t> id(0);

void on_close(int fd)
{    
    LOG_ERROR("on closed.fd[0x%x]",fd);
}

void on_data (int fd,const std::shared_ptr<stdx::tcp::Packet> pkt)
{
    LOG_INFO("on received %s from fd[0x%x] type[0x%x]",pkt->data_.data(),fd,pkt->head_.type_);
}


std::atomic<bool> stop;
unsigned int clt_count(5000);

std::string ip("10.8.64.142");
unsigned short port(12345);

void on_signal(int /*sig*/)
{    
    LOG_ERROR("on signal");
    stop = true;

    for(auto t:v)
    {
        t->clt_->stop();
    }  
}

void on_task_connect(const std::shared_ptr<ClienttType>& t)
{
    if(!t->clt_->is_connected())
    {
        if(t->clt_->connect_to(ip,port,2))
        {
            t->last_tp_=std::chrono::system_clock::now();
        }
    }
}

void on_task_heartbeat(const std::shared_ptr<ClienttType>& t)
{
    auto head = std::make_shared<stdx::tcp::PacketHead>(stdx::tcp::kDefaultHeartbeatReq,time(NULL));

    //for(int i(0); i < 200; ++i)
    {
        ++id;
        head->id_ = id;
        head->time_ = time(NULL);
        if( 0 == t->clt_->send_packet_data("",0,head))
        {
            t->last_tp_ = std::chrono::system_clock::now();
        }
    }
}

void stdx_log(int level,const std::string& msg)
{
   switch (level)
	{
	case stdx::log::ELogLevel::info:
		LOG_INFO(msg.c_str());
		break;

	case stdx::log::ELogLevel::debug:
		LOG_DEBUG(msg.c_str());
		break;

	case stdx::log::ELogLevel::error:
		LOG_ERROR(msg.c_str());
		break;

	case stdx::log::ELogLevel::warn:
		LOG_WARN(msg.c_str());
		break;

	case stdx::log::ELogLevel::fatal:
		LOG_FATAL(msg.c_str());
		break;
	default:
		break;
	}	
}

#ifdef WIN32
int getpid()
{
	return ::GetCurrentProcessId();
}
#endif // WIN32


void init_log()
{   
    stdx::ini::Ini ini;
    ini.load_file("stress_client.ini");

    int log_level(0);
    if(ini.get_bool("log","info").first && ini.get_bool("log","info").second)
    {
        log_level |= stdx::log::ELogLevel::info;
    }
    if(ini.get_bool("log","debug").first && ini.get_bool("log","debug").second)
    {
        log_level |= stdx::log::ELogLevel::debug;
    }
    if(ini.get_bool("log","warn").first && ini.get_bool("log","warn").second)
    {
        log_level |= stdx::log::ELogLevel::warn;
    }
    if(ini.get_bool("log","error").first && ini.get_bool("log","error").second)
    {
        log_level |= stdx::log::ELogLevel::error;
    }
    if(ini.get_bool("log","fatal").first && ini.get_bool("log","fatal").second)
    {
        log_level |= stdx::log::ELogLevel::fatal;
    }

    int log_type(0);
    if(ini.get_bool("log","console").first && ini.get_bool("log","console").second)
    {
        log_type |= stdx::log::ELogOutType::console;
    }
    if(ini.get_bool("log","file").first && ini.get_bool("log","file").second)
    {
        log_type |= stdx::log::ELogOutType::file;
    }

    int size(512);
    if(ini.get_int32("log","size").first)
    {
        size = ini.get_int32("log","size").second;
    }

    bool async(false);
    if(ini.get_bool("log","async").first)
    {
        async = ini.get_bool("log","async").second;
    }

    std::ostringstream oss;
    oss << "stress_client" << getpid() << ".log";

    LOG_START(oss.str(),log_level,log_type,size,async);

    stdx::set_stdx_log_func(stdx_log);
}


int main(int /*arc*/,char** /*arv*/)
{
    stop = false;

    stdx::ini::Ini ini;
    ini.load_file("stress_client.ini");
    if(ini.get_str("tcp","ip").first)
    {
        ip = ini.get_str("tcp","ip").second;
    }

    if(ini.get_int32("tcp","port").first)
    {
        port = ini.get_int32("tcp","port").second;
    }

	int cnt(0);
	int maximum(0);

	if (ini.get_int32("fork", "count").first)
	{
		maximum = ini.get_int32("fork", "count").second;
	}
#ifndef WIN32

	while (cnt < maximum)
	{

		int fpid = fork();
		if (fpid < 0)
		{
			LOG_ERROR("fork failed, err:%s", strerror(errno));
			continue;
		}

		if (fpid == 0)
		{
			break;
		}

		if (fpid > 0)
		{
			++cnt;
			std::this_thread::sleep_for(std::chrono::seconds(30));
		}
	}

#endif // !WIN32


    
    init_log();
    LOG_INFO("stress client start, version:%s",BUILD_TIME);

    signal(SIGTERM,on_signal);

    
  
#ifdef WIN32
	auto evt_ptr = std::make_shared<stdx::ioevent::IOCP>();
	if (!evt_ptr->start(-1))
	{
		return -1;
	}
#else
	auto evt_ptr = std::make_shared<stdx::ioevent::IOEvent>();
	if (!evt_ptr->start(nullptr, nullptr, std::thread::hardware_concurrency()))
	{
		return -1;
	}
#endif // WIN32
	

    stdx::thread::TaskThreadPool ttp_conn;
    if(!ttp_conn.start(16,40))
    {
        return -1;
    }

    LOG_INFO("start stress client");

    for(unsigned int i(0); i < clt_count; ++i)
    {
        auto tc = std::make_shared<ClienttType>(std::make_shared<stdx::tcp::TcpClient>(),std::chrono::system_clock::now());
        if(tc->clt_->start(evt_ptr))
        {          
            tc->clt_->set_on_closed(on_close);
            tc->clt_->set_on_data(on_data);
          
            v.push_back(tc);
            ttp_conn.async_task(on_task_connect,tc);                      
        }else
        {            
            LOG_ERROR("start tcp client failed");
        }
    }
    
    LOG_INFO("create %d clients,remote ip:%s,remote port:%d,count:%d",v.size(),ip.c_str(),port,maximum);

    std::this_thread::sleep_for(std::chrono::milliseconds(10000));

    stdx::thread::TaskThreadPool ttp_hb;
    if(!ttp_hb.start(2,4))
    {
        return -1;
    }

    int dis_cnt(0);
    do
    {
        dis_cnt = 0;
        using namespace std::chrono;
        for(auto t:v)
        {
            if(t)
            {
                if(!t->clt_->is_connected())
                {
                    ++dis_cnt;
                    if(ttp_conn.task_count() < 80)
                    {
                        ttp_conn.async_task(on_task_connect,t);
                    }
                    
                    continue;
                }

                int16_t diff = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count() -
                            duration_cast<milliseconds>(t->last_tp_.time_since_epoch()).count();

                if(diff > 3000 && ttp_conn.task_count() < 80)
                {
                    ttp_hb.async_task(on_task_heartbeat,t);
                }
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    }while (dis_cnt < 4500);
    
    

    ttp_conn.stop();
    ttp_hb.stop();

    evt_ptr->stop();

    LOG_INFO("stoped, disconnected count %d",dis_cnt);

    LOG_STOP();
    
    return 0;
}