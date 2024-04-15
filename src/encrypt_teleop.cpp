#include "ros/ros.h"
#include "std_msgs/String.h"
#include "std_msgs/Float64.h"
#include <image_transport/image_transport.h>
#include <opencv2/opencv.hpp>
#include <cv_bridge/cv_bridge.h>
extern "C"{                 // we need this otherwise it can't find the functions
    #include "crypto_aead.h"
    #include <openssl/evp.h>
    #include <openssl/aes.h>
    #include <openssl/err.h>
    #include <api.h>
}
#include <string>
#include <vector>

//TODO: move ASCON and SSL functions to a header file

//https://github.com/ros/ros_tutorials/tree/noetic-devel/roscpp_tutorials
//These people rolled their own ROS crypto (bad idea): https://github.com/oysteinvolden/Real-time-sensor-encryption/tree/master 

using namespace std;

class GenericMessage{
    public:
        string name;
        static ros::NodeHandle node;
        ros::Subscriber sub;
        ros::Publisher pub;

        // Example values for crypto 
        std::string associatedData = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
        std::array<unsigned char, CRYPTO_NPUBBYTES> nonce = { 0, 1, 2,  3,  4,  5,  6,  7, 8, 9, 10, 11, 12, 13, 14, 15 };
        std::array<unsigned char, CRYPTO_KEYBYTES> key = { 0, 1, 2,  3,  4,  5,  6,  7, 8, 9, 10, 11, 12, 13, 14, 15 };

    
    GenericMessage(string n, string type): name(n){
        setupSubscriber();
        pub = node.advertise<std_msgs::String>("crypto/" + type + name, 1);
    }

    virtual void setupSubscriber(){
        sub = node.subscribe(name, 1, &GenericMessage::Callback, this);
    }

    void Callback(const std_msgs::Float64::ConstPtr& msg) {
    // void Callback(const string &msg) {
        // Encrypt robot status data and publish
        //TODO: convert to string & add topic name
        auto encrypted = ascon_encrypt(msg, associatedData, nonce, key);
        pub.publish(encrypted);
    }
};

class StatusMessage : GenericMessage{
    public:
        StatusMessage(string name) : GenericMessage(name, "status"){}
};
class CommandMessage : GenericMessage{
    public:
        CommandMessage(string name) : GenericMessage(name, "command"){}
};
class VideoMessage : GenericMessage{
    public:
        VideoMessage(string name) : GenericMessage(name, "video"){}
    
    void setupSubscriber() override{
        sub = node.subscribe(name, 1, &VideoMessage::Callback, this);
    }

    void Callback(const sensor_msgs::ImageConstPtr& msg) {
        //Message definition for image: https://docs.ros.org/en/noetic/api/sensor_msgs/html/msg/Image.html 
        
        // Convert ROS image message to OpenCV image
        cv_bridge::CvImagePtr cv_ptr;
        cv_ptr = cv_bridge::toCvCopy(msg, sensor_msgs::image_encodings::BGR8);

        // Convert OpenCV image to string
        std::vector<uchar> buffer;
        cv::imencode(".jpg", cv_ptr->image, buffer);
        std::string image_str(buffer.begin(), buffer.end());

        //Encrypt image string and publish
        auto encrypted = ascon_encrypt(image_str, associatedData,nonce,key);
        pub.publish(encrypted);
    }
};

class EncryptPayload
{
private:
    ros::NodeHandle n; 

    vector<StatusMessage> status_subs;
    vector<CommandMessage> command_subs;
    vector<VideoMessage> video_subs;

    
public:

    EncryptPayload(){
        vector<string> status_topics = {"/pose/heave", "/pose/yaw"};
        vector<string> command_topics = {"/output_wrench/surge", "/output_wrench/sway", "/output_wrench/heave", "/output_wrench/yaw", "/output_wrench/pitch", "/output_wrench/roll"};
        vector<string> video_topics = {"/zed2/zed_node/rgb/image_rect_color"};
        
        for (const std::string& topic : status_topics) {
            status_subs.push_back(StatusMessage(topic));
        }
        for (const std::string& topic : command_topics) {
            command_subs.push_back(CommandMessage(topic));
        }
        for (const std::string& topic : video_topics) {
            video_subs.push_back(VideoMessage(topic));
        }
    }
};


int main(int argc, char **argv)
{
    //Define ROS node "encrypt_teleop"
    ros::init(argc, argv, "encrypt_teleop");

    //Define instance of class
    EncryptPayload e;

    //TODO: Set Hertz to match frequency of what we're sending
    //Set the frequency of the update to 30 Hz
    ros::Rate loop_rate(30);

    //Allows for subscribers to be handled asynchronously using available threads 
    ros::AsyncSpinner s(0);
    s.start();

    while(ros::ok())
    {
        loop_rate.sleep();
    }

}