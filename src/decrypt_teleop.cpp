#include "ros/ros.h"
#include "std_msgs/String.h"
#include "std_msgs/Float64.h"
#include <image_transport/image_transport.h>
#include <opencv2/opencv.hpp>
#include <cv_bridge/cv_bridge.h>
extern "C"
{ // we need this otherwise it can't find the functions
#include "crypto_aead.h"
// #include <openssl/evp.h>
// #include <openssl/aes.h>
// #include <openssl/err.h>
#include <api.h>
}
#include <string>
#include <vector>
#include "crypto_helpers.h"
#include <iostream>

using std::cout;

// TODO: move ASCON and SSL functions to a header file
// beddy this should be good to go for ASCON once we figure out how to link it

// https://github.com/ros/ros_tutorials/tree/noetic-devel/roscpp_tutorials
// These people rolled their own ROS crypto (bad idea): https://github.com/oysteinvolden/Real-time-sensor-encryption/tree/master

class GenericDecrypt
{
public:
    std::string pub_name;
    std::string sub_name;
    static ros::NodeHandle *node;
    ros::Subscriber sub;
    ros::Publisher pub;

    // Example values for crypto
    std::string associatedData = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    std::array<unsigned char, CRYPTO_NPUBBYTES> nonce = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    std::array<unsigned char, CRYPTO_KEYBYTES> key = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    GenericDecrypt(std::string name)
    {   
        sub_name = "encrypt/crypto" + name;
        pub_name = "plaintext" + name;

        setupSubscriber();
        setupPublisher();
    }

    virtual void setupSubscriber()
    {
        cout << "Subscriber" << sub_name << "\n";
        sub = node->subscribe(sub_name, 1, &GenericDecrypt::Callback, this);
    }

    virtual void setupPublisher(){
        cout << "Publisher" << sub_name << "\n";
        pub = node->advertise<std_msgs::Float64>(pub_name, 1);
    }

    void Callback(const std_msgs::String::ConstPtr &msg)
    {
        // Decrypt robot status data and publish
        std::string decrypted = ascon_decrypt(msg->data, associatedData, nonce, key);
        
        double double_decrypt = *reinterpret_cast<double*>(decrypted.data());
        std_msgs::Float64 decrypted_double;
        decrypted_double.data = double_decrypt;
        pub.publish(decrypted_double);
    }
};

class DecryptStatus : GenericDecrypt
{
public:
    DecryptStatus(std::string name) : GenericDecrypt(name) {}
};
class DecryptCommand : GenericDecrypt
{
public:
    DecryptCommand(std::string name) : GenericDecrypt(name) {}
};

class DecryptVideo : GenericDecrypt
{
public:
    DecryptVideo(std::string name) : GenericDecrypt(name) {}

    void setupSubscriber() override
    {
        sub = node->subscribe(sub_name, 1, &DecryptVideo::Callback, this);
    }

    void setupPublisher() override{
        pub = node->advertise<sensor_msgs::Image>(pub_name, 1);
    }

    void Callback(const std_msgs::String::ConstPtr &msg)
    {
        /// Decrypt image string
        auto decrypted = ascon_decrypt(std::string_view(reinterpret_cast<const char*>(&(msg->data)), sizeof(double)), associatedData, nonce, key);

        // Convert image string to OpenCV image
        std::vector<uchar> buffer(decrypted.begin(), decrypted.end());
        cv::Mat image = cv::imdecode(buffer, cv::IMREAD_COLOR);

        // Convert OpenCV image to ROS image message
        cv_bridge::CvImage cv_image;
        cv_image.image = image;
        cv_image.encoding = sensor_msgs::image_encodings::BGR8;
        
        // TODO: Are we publishing Image or ImagePtr??
        sensor_msgs::ImagePtr ros_image = cv_image.toImageMsg();

        // Publish decrypted image
        pub.publish(ros_image);
    }
};


int main(int argc, char **argv)
{
    // Define ROS node "decrypt_teleop"
    ros::init(argc, argv, "decrypt_teleop");

    // Define instance of class
    GenericDecrypt::node = new ros::NodeHandle();
    Payload<GenericDecrypt, GenericDecrypt, DecryptVideo> e;

    // TODO: Set Hertz to match frequency of what we're sending
    // Set the frequency of the update to 30 Hz
    ros::Rate loop_rate(30);

    // Allows for subscribers to be handled asynchronously using available threads
    ros::AsyncSpinner s(4);
    s.start();

    while (ros::ok())
    {
        loop_rate.sleep();
    }

    delete GenericDecrypt::node;
}

ros::NodeHandle *GenericDecrypt::node = nullptr;
