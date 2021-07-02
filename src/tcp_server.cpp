
#include "stdx.h"
#include "version.h"
#include "tcp/tcp_listener.h"
#include "tcp/tcp_linker.h"
#include "tcp/packet.h"
#include "log/log.h"
#include "timer/timer.h"
#include "ini/ini.h"

#include <signal.h>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <iostream>
#include <fcntl.h>

#ifdef WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif // WIN32



std::condition_variable cond;
std::mutex mtx;
stdx::tcp::TcpListener* ptcp;

#ifdef WIN32
HANDLE h_event;
#endif // WIN32


void on_accept(int fd, unsigned short port, const std::string ip)
{
    LOG_INFO("accept from %s:%d fd[%d]",ip.c_str(),port,fd);
}

void on_data(int fd, unsigned short port, const std::string ip, std::shared_ptr<stdx::tcp::Packet> pkt)
{
    //std::string cmd(pkt->data_);
    time_t t_now = time(NULL);
    long df = t_now - pkt->head_.time_;
    LOG_INFO("received data %s,tp[%d] diff[%ld] from %s:%d fd[0x%x] type[0x%x] id[%d]",(pkt->data_.empty() ? " " : pkt->data_.data()),(int)t_now,df,ip.c_str(),port,fd,pkt->head_.type_,pkt->head_.id_);

    if(df > 2)
    {
       // LOG_ERROR("received %d seconds later",df);
        LOG_ERROR("received data %s,tp[%d] diff[%ld] from %s:%d fd[0x%x] type[0x%x] id[%d]",(pkt->data_.empty() ? " " : pkt->data_.data()),(int)t_now,df,ip.c_str(),port,fd,pkt->head_.type_,pkt->head_.id_);
    }

    if("ping" == std::string(pkt->data_.begin(),pkt->data_.end()) && stdx::tcp::kDefaultHeartbeatReq != pkt->head_.type_)
    {
        if(NULL != ptcp)
        {
            auto head = std::make_shared<stdx::tcp::PacketHead>(pkt->head_.type_|stdx::tcp::kPacketTypeMask,pkt->head_.id_);
            ptcp->send_packet_data_by_fd(fd,"pang",4,head);
        }
    }

    //std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
}

void on_close(int fd, unsigned short /*port*/, const std::string ip)
{
    LOG_INFO("on close, fd[0x%x] ip:%s",fd,ip.c_str());
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

std::tuple<int,int,int,bool> get_log_cfg()
{
    stdx::ini::Ini ini;
    ini.load_file("tcpserver.ini");

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

    return std::tuple<int,int,int,bool>(log_level,log_type,size,async);
}

void init_log()
{
    auto cfg = get_log_cfg();    

    LOG_START("tcpserver.log",std::get<0>(cfg),std::get<1>(cfg),std::get<2>(cfg),std::get<3>(cfg));

    stdx::set_stdx_log_func(stdx_log);
}

void reload_log_cfg()
{
	auto cfg = get_log_cfg();
	stdx::log::Logger::instance().set_level_mask(std::get<0>(cfg));
	stdx::log::Logger::instance().set_out_type_mask(std::get<1>(cfg));
	stdx::log::Logger::instance().set_max_file_size(std::get<2>(cfg));

	LOG_INFO("log config reloaded");

	std::cout << "log config reloaded" << std::endl;
}

#ifdef WIN32
bool stop(false);
#else

void on_signal(int sig)
{
	LOG_INFO("on signal %d", sig);

	if (10 == sig) //SIGUSR1,reload config
	{
		reload_log_cfg();
		return;
	}

	cond.notify_all();
}

//first:process is running, second: the running pid
std::pair<bool, int> get_exist_pid()
{
	bool lck(false);
	int pid(0);
	int fd = open(".tcpserver.lck", O_RDWR);
	if (fd < 0)
	{
		return std::pair<bool, int>(false, 0);
	}

	int ret = lockf(fd, F_TEST, 0);

	if (-1 == ret)
	{
		std::vector<char> buffer(32, '\0');
		auto len = read(fd, &buffer[0], 32);
		if (len > 0)
		{
			pid = std::stol(buffer.data());
			lck = true;
		}
	}

	close(fd);

	return std::pair<bool, int>(lck, pid);
}

int lock_fd(-1);

bool lock()
{
	int fd = open(".tcpserver.lck", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
	if (fd < 0)
	{
		std::cerr << "open lock file failed:" << errno << std::endl;
		return false;
	}

	bool ret(false);

	int i = lockf(fd, F_TLOCK, 0);
	if (i == 0)
	{
		std::ostringstream oss;
		oss << getpid();
		write(fd, oss.str().c_str(), oss.str().size());

		ret = true;
	}
	lock_fd = fd;
	//close(fd);
	return ret;
}

void un_lock()
{
	lockf(lock_fd, F_ULOCK, 0);
	close(lock_fd);
	std::remove(".tcpserver.lck");
}
#endif // WIN32



int process_cmd(const std::string& cmd)
{
    if("-v" == cmd || "--version" == cmd)
    {
        std::cout << "version:" << BUILD_TIME << std::endl;
        return 0;
    }

    if("-r" == cmd || "--reload" == cmd)
    {
        
#ifdef WIN32
		h_event = CreateEventA(NULL, FALSE, FALSE, "__EVENT_TCPSERVER_{D6F4B56F-F6C8-4024-B24F-BA99127197F4}");
		if (ERROR_ALREADY_EXISTS != GetLastError())
		{
			std::cerr << "no tcpserver is running" << std::endl;
			return -1;
		}

		SetEvent(h_event);
		std::cout << "reload event sent" << std::endl;
#else
		auto ex = get_exist_pid();
		if (!ex.first)
		{
			std::cerr << "no tcpserver is running" << std::endl;
			return -1;
		}
		kill(ex.second, SIGUSR1);
		std::cout << "send reload signal to pid " << ex.second << " succeeded" << std::endl;
#endif // WIN32
		       

        return 0;
    }

    //std::cout << "unknown cmd:" << cmd << std::endl;
    std::cout << "usage:\n" << "-v or --version : check version\n" << "-r or --reload: reload config\n" << std::endl;

    return -1;
}

int main(int argc, char** argv)
{
    if(argc > 1)
    {
        return process_cmd(argv[1]);
    }
#ifdef WIN32
	h_event = CreateEventA(NULL, FALSE, FALSE, "__EVENT_TCPSERVER_{D6F4B56F-F6C8-4024-B24F-BA99127197F4}");
	if (ERROR_ALREADY_EXISTS == GetLastError())
	{
		std::cerr << "tcpserver is already running" << std::endl;
		return -1;
	}
#else
	auto ex = get_exist_pid();
	if (ex.first)
	{
		std::cerr << "tcpserver is already running,pid:" << ex.second << std::endl;
		return -1;
	}

	if (!lock())
	{
		std::cerr << "create locak failed";
		return -1;
	}
#endif // WIN32

    

    init_log();
    
    LOG_INFO("start tcpserver version:%s",BUILD_TIME);

#ifdef WIN32
	auto trd = std::thread([]() {
		while (!stop)
		{
			WaitForSingleObject(h_event, INFINITE);
			reload_log_cfg();
		}
		CloseHandle(h_event);
	});

	trd.detach();
#else
    signal(SIGQUIT,on_signal);    
    signal(SIGTERM,on_signal);
    signal(SIGSEGV,on_signal);
    signal(SIGUSR1,on_signal);     
#endif

    //std::cout << "Hello, world!\n";
    unsigned short port(12345);
    stdx::ini::Ini ini;
    ini.load_file("tcpserver.ini");
    if(ini.get_int32("tcp","port").first)
    {
        port = ini.get_int32("tcp","port").second;
    }

    int timeout(30000);
    if(ini.get_int32("tcp","timeout").first)
    {
        timeout = ini.get_int32("tcp","timeout").second;
    }

    stdx::tcp::TcpListener tcp_listener(port);
    tcp_listener.set_on_accept(on_accept);
    tcp_listener.set_on_data(on_data);
    tcp_listener.set_on_close(on_close);
    tcp_listener.set_conn_timeout(timeout);
   
    if(!tcp_listener.start())
    {        
        LOG_ERROR("Start tcp server failed");
        LOG_STOP();
        return -1;
    }

    LOG_INFO("tlistening on:%d",port);

    ptcp=&tcp_listener;

    stdx::timer::Timer timer;
    auto head = std::make_shared<stdx::tcp::PacketHead>(123,0);
    if(timer.start())
    {
        timer.add_timer(1,300000,[&tcp_listener,&head](stdx::timer::Timer*,int){
            std::string data = std::to_string(time(NULL));
            
            tcp_listener.broadcast_packet_data(data.data(),data.size(),head);
        });
    }
    

    std::unique_lock<std::mutex> lck(mtx);
    cond.wait(lck);

    tcp_listener.stop();

    LOG_INFO("tcp server stop");
#ifdef WIN32
    stop = true;
	SetEvent(h_event);
	
#else
    un_lock();	
#endif

    LOG_STOP();

    return 0;    
}
