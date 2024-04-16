#include "ros/ros.h"
#include "std_msgs/String.h"
#include "std_msgs/Float64.h"
#include <image_transport/image_transport.h>
#include <opencv2/opencv.hpp>
#include <cv_bridge/cv_bridge.h>
#include "crypto_helpers.h"
#include <iostream>

using std::cout;

//TODO: move ASCON and SSL functions to a header file

//https://github.com/ros/ros_tutorials/tree/noetic-devel/roscpp_tutorials
//These people rolled their own ROS crypto (bad idea): https://github.com/oysteinvolden/Real-time-sensor-encryption/tree/master 

class EncryptPayload
{
private:
    ros::NodeHandle n; 

    // Publishers for hypothesized teleoperation categories
    ros::Publisher status_pub = n.advertise<std_msgs::String>("crypto/status_message", 1);
    ros::Publisher command_pub = n.advertise<std_msgs::String>("crypto/command_message", 1);
    ros::Publisher video_pub = n.advertise<std_msgs::String>("crypto/video", 1);

    // Robot status topics
    ros::Subscriber status_sub_heave = n.subscribe("/pose/heave", 1, &EncryptPayload::RobotStatusCallback, this);
    ros::Subscriber status_sub_yaw = n.subscribe("/pose/yaw", 1, &EncryptPayload::RobotStatusCallback, this);

    // Robot command topics
    ros::Subscriber command_sub_surge = n.subscribe("/output_wrench/surge", 1, &EncryptPayload::RobotCommandCallback, this);
    ros::Subscriber command_sub_sway = n.subscribe("/output_wrench/sway", 1, &EncryptPayload::RobotCommandCallback, this);
    ros::Subscriber command_sub_heave = n.subscribe("/output_wrench/heave", 1, &EncryptPayload::RobotCommandCallback, this);
    ros::Subscriber command_sub_yaw = n.subscribe("/output_wrench/yaw", 1, &EncryptPayload::RobotCommandCallback, this);
    ros::Subscriber command_sub_pitch = n.subscribe("/output_wrench/pitch", 1, &EncryptPayload::RobotCommandCallback, this);
    ros::Subscriber command_sub_roll = n.subscribe("/output_wrench/roll", 1, &EncryptPayload::RobotCommandCallback, this);

    // Video topic
    ros::Subscriber video_sub = n.subscribe("/zed2/zed_node/rgb/image_rect_color", 1, &EncryptPayload::RobotVideoCallback, this);

    // Example values for crypto 
    std::string associatedData{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    std::array<unsigned char, CRYPTO_NPUBBYTES> nonce{ 0, 1, 2,  3,  4,  5,  6,  7, 8, 9, 10, 11, 12, 13, 14, 15 };
    std::array<unsigned char, CRYPTO_KEYBYTES> key{ 0, 1, 2,  3,  4,  5,  6,  7, 8, 9, 10, 11, 12, 13, 14, 15 };


public:
    void RobotStatusCallback(const std_msgs::Float64::ConstPtr& msg) {
        // Encrypt robot status data and publish
        std::string encrypted = ascon_encrypt(std::string_view(reinterpret_cast<const char*>(&(msg->data)), sizeof(double)), associatedData, nonce, key);
        std_msgs::String string_encrypted;
        string_encrypted.data = encrypted.data();
        status_pub.publish(string_encrypted);
    }

    void RobotCommandCallback(const std_msgs::Float64::ConstPtr& msg) {
        // Encrypt robot command data and publish
        std::string encrypted = ascon_encrypt(std::string_view(reinterpret_cast<const char*>(&(msg->data)), sizeof(double)), associatedData, nonce, key);
        std_msgs::String string_encrypted;
        string_encrypted.data = encrypted.data();
        command_pub.publish(string_encrypted);
    }

    void RobotVideoCallback(const sensor_msgs::ImageConstPtr& msg) {
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
        video_pub.publish(encrypted_string);
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
    ros::AsyncSpinner s(4);
    s.start();
    cout << "hello\n";
    while(ros::ok())
    {
        loop_rate.sleep();
    }
    cout << "goodbye\n";

}