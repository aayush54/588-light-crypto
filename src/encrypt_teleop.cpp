#include "ros/ros.h"
#include "std_msgs/String.h"
#include "std_msgs/Float64.h"
#include <image_transport/image_transport.h>
#include <opencv2/opencv.hpp>
#include <cv_bridge/cv_bridge.h>
#include "crypto_helpers.h"
#include <string_view>
#include <iostream>

//https://github.com/ros/ros_tutorials/tree/noetic-devel/roscpp_tutorials
//These people rolled their own ROS crypto (bad idea): https://github.com/oysteinvolden/Real-time-sensor-encryption/tree/master 

class GenericEncrypt{
    public:
        std::string pub_name;
        std::string sub_name;
        static ros::NodeHandle *node;
        ros::Subscriber sub;
        ros::Publisher pub;

        // Example values for crypto 
        std::string associatedData = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
        std::array<unsigned char, CRYPTO_NPUBBYTES> nonce = { 0, 1, 2,  3,  4,  5,  6,  7, 8, 9, 10, 11, 12, 13, 14, 15 };
        std::array<unsigned char, CRYPTO_KEYBYTES> key = { 0, 1, 2,  3,  4,  5,  6,  7, 8, 9, 10, 11, 12, 13, 14, 15 };

    
    GenericEncrypt(std::string name){
        sub_name = name;
        pub_name = "crypto" + name;

        setupSubscriber();
        setupPublisher();
    }


    virtual void setupSubscriber(){
        sub = node->subscribe(sub_name, 1, &GenericEncrypt::Callback, this);
    }

    virtual void setupPublisher(){
        pub = node->advertise<std_msgs::String>(pub_name, 1);
    }

    void Callback(const std_msgs::Float64::ConstPtr& msg) {
        // Encrypt robot status data and publish
        std::string encrypted = ascon_encrypt(std::string_view(reinterpret_cast<const char*>(&(msg->data)), sizeof(double)), associatedData, nonce, key);
        std_msgs::String string_encrypted;
        string_encrypted.data = encrypted.data();
        pub.publish(string_encrypted);
    }
};

class EncryptStatus : GenericEncrypt{
    public:
        EncryptStatus(std::string name) : GenericEncrypt(name){}
};
class EncryptCommand : GenericEncrypt{
    public:
        EncryptCommand(std::string name) : GenericEncrypt(name){}
};
class EncryptVideo : GenericEncrypt{
    public:
        EncryptVideo(std::string name) : GenericEncrypt(name){}
    
    void setupSubscriber() override{
        sub = node->subscribe(sub_name, 1, &EncryptVideo::Callback, this);
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
        std_msgs::String encrypted_string;
        encrypted_string.data = encrypted.data();
        pub.publish(encrypted_string);
    }
};


int main(int argc, char **argv)
{
    //Define ROS node "encrypt_teleop"
    ros::init(argc, argv, "encrypt_teleop");

    //Define instance of class
    GenericEncrypt::node = new ros::NodeHandle();
    Payload<EncryptStatus, EncryptCommand, EncryptVideo> e;

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
    delete GenericEncrypt::node;
}

ros::NodeHandle *GenericEncrypt::node;