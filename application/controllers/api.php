<?php
defined('BASEPATH') or exit('No direct script access allowed');

use Restserver\Libraries\REST_Controller;
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE");

class api extends REST_Controller
{
    public function __construct()
    {
        parent::__construct();
        $this->load->helper(['jwt', 'authorization']);
    }

    public function hello_get()
    {
        $tokenData = 'Hello World!';
        $token = AUTHORIZATION::generateToken($tokenData);
        $status = parent::HTTP_OK;
        $response = ['status' => $status, 'token' => $token];
        $this->response($response, $status);
    }

    public function login_post()
    {
        $dummy_user = [
            'username' => 'test',
            'password' => 'test'
        ];
        $username = $this->post('username');
        $password = $this->post('password');
        $token = password_hash($password, PASSWORD_BCRYPT);

        if ($username === $dummy_user['username'] && $password === $dummy_user['password']) {
            $token = AUTHORIZATION::generateToken(['token' => $token]);
            $status = parent::HTTP_OK;
            $response = ['status' => $status, 'token' => $token];
            $this->response($response, $status);
        } else {
            $this->response(['msg' => 'Invalid username or password!'], parent::HTTP_NOT_FOUND);
        }
    }

    private function verify_request()
    {

        $headers = $this->input->request_headers();
        if (isset($headers['Authorization'])) {
            $header = $headers['Authorization'];
        } else {
            $status = parent::HTTP_UNAUTHORIZED;
            $response = ['status' => $status, 'msg' => 'Unauthorized Access!'];
            return $response;
        }

        $token = explode(" ", $header)[1];

        try {
            $data = AUTHORIZATION::validateToken($token);

            if ($data === false) {
                $status = parent::HTTP_UNAUTHORIZED;
                $response = ['status' => $status, 'msg' => 'Unauthorized Access!'];
            } else {
                $response = ['status' => 200, 'msg' => $data];
            }

            return $response;
        } catch (Exception $e) {
            $status = parent::HTTP_UNAUTHORIZED;
            $response = ['status' => $status, 'msg' => 'Unauthorized Access! '];
            return $response;
        }
    }

    public function get_me_data_post()
    {
        $data = $this->verify_request();
        $status = parent::HTTP_OK;
        $response = ['status' => $status, 'data' => $data];
        $this->response($response, $status);
    }
}