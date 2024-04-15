#include "ros/ros.h"
#include "std_msgs/String.h"
#include <image_transport/image_transport.h>
#include <opencv2/opencv.hpp>
#include <cv_bridge/cv_bridge.h>

//TODO: move ASCON and SSL functions to a header file
//beddy this should be good to go for ASCON once we figure out how to link it

//https://github.com/ros/ros_tutorials/tree/noetic-devel/roscpp_tutorials
//These people rolled their own ROS crypto (bad idea): https://github.com/oysteinvolden/Real-time-sensor-encryption/tree/master 

class DecryptPayload
{
private:
    ros::NodeHandle n; 

    // Subscribers for hypothesized teleoperation categories
    ros::Subscriber status_sub = n.subscribe("crypto/status_message", 1, &EncryptPayload::RobotStatusCallback, this);
    ros::Subscriber command_sub = n.subscribe("crypto/command_message", 1, &EncryptPayload::RobotCommandCallback, this);
    ros::Subscriber video_sub = n.subscribe("crypto/video", 1, &EncryptPayload::RobotVideoCallback, this);

    // Publishers for decrypted data
    // Robot status topics
    ros::Subscriber status_sub = n.advertise<std_msgs::Float64>("/teleop/pose/heave", 1);
    ros::Subscriber status_sub = n.advertise<std_msgs::Float64>("/teleop/pose/yaw", 1);

    // Robot command topics
    ros::Publisher command_pub_surge = n.advertise<std_msgs::Float64>("/teleop/surge", 1);
    ros::Publisher command_pub_sway = n.advertise<std_msgs::Float64>("/teleop/sway", 1);
    ros::Publisher command_pub_heave = n.advertise<std_msgs::Float64>("/teleop/heave", 1);
    ros::Publisher command_pub_yaw = n.advertise<std_msgs::Float64>("/teleop/yaw", 1);
    ros::Publisher command_pub_pitch = n.advertise<std_msgs::Float64>("/teleop/pitch", 1);
    ros::Publisher command_pub_roll = n.advertise<std_msgs::Float64>("/teleop/roll", 1);
    
    // Video topic
    ros::Publisher video_pub = n.advertise<std_msgs::String>("teleop/video", 1);

    // Example values for crypto 
    std::string associatedData{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    std::array<unsigned char, CRYPTO_NPUBBYTES> nonce{ 0, 1, 2,  3,  4,  5,  6,  7, 8, 9, 10, 11, 12, 13, 14, 15 };
    std::array<unsigned char, CRYPTO_KEYBYTES> key{ 0, 1, 2,  3,  4,  5,  6,  7, 8, 9, 10, 11, 12, 13, 14, 15 };

    
public:
    void RobotStatusCallback(const std_msgs::Float64::ConstPtr& msg) {
        // Decrypt robot status data and publish
        auto decrypted = ascon_decrypt(msg, associatedData, nonce, key);
        
        //TODO: use switch statement to publish to right topic?
        status_pub.publish(encrypted);
    }

    void RobotCommandCallback(const std_msgs::Float64::ConstPtr& msg) {
        // Decrypt robot command data and publish
        auto decrypted = ascon_decrypt(msg, associatedData, nonce, key);
        
        //TODO: use switch statement to publish to right topic?
        command_pub.publish(encrypted);
    }

    void RobotVideoCallback(const sensor_msgs::Float64::ConstPtr& msg) {
        //Decrypt image string
        auto decrypted = ascon_decrypt(msg, associatedData, nonce, key);
        
        // Convert image string to OpenCV image
        std::vector<uchar> buffer(decrypted.begin(), decrypted.end());
        cv::Mat image = cv::imdecode(buffer, cv::IMREAD_COLOR);

        // Convert OpenCV image to ROS image message
        cv_bridge::CvImage cv_image;
        cv_image.image = image;
        cv_image.encoding = sensor_msgs::image_encodings::BGR8;
        sensor_msgs::ImagePtr ros_image = cv_image.toImageMsg();

        //Publish decrypted image
        video_pub.publish(ros_image);
    }
};

int main(int arc, char **argv)
{
    //Define ROS node "decrypt_teleop"
    ros::init(argc, argv, "decrypt_teleop");

    //Define instance of class
    DecryptPayload e;

    //TODO: Set Hertz to match frequency of what we're sending
    //Set the frequency of the update to 30 Hz
    ros::Rate loop_rate(30);

    //Allows for subscribers to be handled asynchronously using available threads 
    ros::AsyncSpinner s;
    s.start();

    while(ros::ok())
    {
        loop_rate.sleep();
    }

}