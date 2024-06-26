#include "ros/ros.h"
#include "std_msgs/String.h"
#include "std_msgs/Float64.h"
#include <image_transport/image_transport.h>
#include <opencv2/opencv.hpp>
#include <cv_bridge/cv_bridge.h>
#include "crypto_helpers.h"
#include <string_view>
#include <iostream>

using std::cout;

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
        //const std::string associatedData = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	const std::string associatedData = "012345678910";
        //const std::array<unsigned char, CRYPTO_NPUBBYTES> nonce = { 0, 1, 2,  3,  4,  5,  6,  7, 8, 9, 10, 11, 12, 13, 14, 15 };
        const std::array<unsigned char, CRYPTO_KEYBYTES> key = { 0, 1, 2,  3,  4,  5,  6,  7, 8, 9, 10, 11, 12, 13, 14, 15 };

    
    GenericEncrypt(std::string name){
        sub_name = name;
        pub_name = "crypto" + name;

        setupSubscriber();
        setupPublisher();
    }


    virtual void setupSubscriber(){
        cout << "Subscriber" << sub_name << "\n";
        sub = node->subscribe(sub_name, 1, &GenericEncrypt::Callback, this);
    }

    virtual void setupPublisher(){
        cout << "Publisher" << pub_name << "\n";
        pub = node->advertise<std_msgs::String>(pub_name, 1);
    }

    void Callback(const std_msgs::Float64::ConstPtr& msg) {
	// Encrypt robot status data and publish
	//const char* bytePtr = reinterpret_cast<const char*>(&(msg->data));
	//std::string byteString(bytePtr, sizeof(double));
	const std::array<unsigned char, CRYPTO_NPUBBYTES> nonce = { 0, 1, 2,  3,  4,  5,  6,  7, 8, 9, 10, 11, 12, 13, 14, 15 };

	    std::string msg_str = std::to_string(msg->data);
	std::string_view msg_str_view(msg_str);
	std::string encrypted= ascon_encrypt(msg_str_view, associatedData, nonce, key);
	//std::string encrypted = ascon_encrypt(std::string_view(reinterpret_cast<const char*>(&(msg->data)), sizeof(double)), associatedData, nonce, key);
	std::string_view encrypted_msg_str_view(encrypted);
	cout << "STRING VIEW: "; 
	printBytes(encrypted_msg_str_view);
	cout << "associated: " << associatedData << " ";
	printBytes(associatedData);
	cout << "nonce: ";
	printBytes(nonce);
	cout << "key: ";
        printBytes(key);

	std::string decrypted = ascon_decrypt(encrypted_msg_str_view, associatedData, nonce, key);
	cout << "gobble gook: " << decrypted << "\n";
	std_msgs::String string_encrypted;
        string_encrypted.data = encrypted;
        pub.publish(string_encrypted);
    } 
};

class VideoEncrypt
{
public:
    std::string sub_name;
    std::string pub_name;
    
    ros::Subscriber sub;
    ros::Publisher pub;

    // Example values for crypto
    const std::string associatedData = "012345678910";
    std::array<unsigned char, CRYPTO_KEYBYTES> key = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    VideoEncrypt(const std::string &name)
    {
        ros::NodeHandle* &node = GenericEncrypt::node;
        sub_name = name;
        pub_name = "crypto" + name;

        cout << "Video Sub " << sub_name << " \n";
        sub = node->subscribe(sub_name, 1, &VideoEncrypt::Callback, this);
        
        cout << "Publisher " << pub_name << "\n";
        pub = node->advertise<std_msgs::String>(pub_name, 1);
    }

    void Callback(const sensor_msgs::ImageConstPtr &msg)
    {
        // Message definition for image: https://docs.ros.org/en/noetic/api/sensor_msgs/html/msg/Image.html
	std::array<unsigned char, CRYPTO_NPUBBYTES> nonce = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        cout << "Video Callback\n";
        // Convert ROS image message to OpenCV image
        cv_bridge::CvImagePtr cv_ptr;
        cv_ptr = cv_bridge::toCvCopy(msg, sensor_msgs::image_encodings::BGR8);

        // Convert OpenCV image to string
        std::vector<uchar> buffer;
        cv::imencode(".jpg", cv_ptr->image, buffer);
        std::string image_str(buffer.begin(), buffer.end());

        // Encrypt image string and publish
        auto encrypted = ascon_encrypt(image_str, associatedData, nonce, key);
        std_msgs::String encrypted_string;
        encrypted_string.data = encrypted.data();
        cout << encrypted << "\n";
        pub.publish(encrypted_string);
    }
};


int main(int argc, char **argv)
{
    //Define ROS node "encrypt_teleop"
    ros::init(argc, argv, "encrypt_teleop");

    //Define instance of class
    GenericEncrypt::node = new ros::NodeHandle();
    Payload<GenericEncrypt, GenericEncrypt, VideoEncrypt> e;

    //TODO: Set Hertz to match frequency of what we're sending
    //Set the frequency of the update to 30 Hz
    ros::Rate loop_rate(30);

    //Allows for subscribers to be handled asynchronously using available threads 
    ros::AsyncSpinner s(1);
    s.start();

    while(ros::ok())
    {
        loop_rate.sleep();
    }
    delete GenericEncrypt::node;
}

ros::NodeHandle *GenericEncrypt::node;
