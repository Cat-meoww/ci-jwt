<?php

namespace App\Controllers\API;

use App\Models\UserModel;
use App\Models\RefreshTokens;

use CodeIgniter\API\ResponseTrait;
use App\Controllers\BaseController;
use Exception;
use Firebase\JWT\JWT;
use Ramsey\Uuid\Uuid;
use \CodeIgniter\HTTP\RequestInterface;


class Auth extends BaseController
{
    use ResponseTrait;
    public $session;
    public $data;
    public $usermodel;
    public $errors;
    public function __construct()
    {
        helper('cookie');
        $this->session = session();
        $this->usermodel = new UserModel();
        $this->request = \Config\Services::request();
    }

    public function login()
    {
        try {
            $rules = [
                'email'    => 'required|valid_email',
                'password' => 'required|min_length[5]|max_length[225]|validate_user[email,password]',
            ];
            $error = [
                'email' => ['valid_email' => "Require valid mail id"]
            ];
            if (!$this->validate($rules, $error)) {
                $this->errors = $this->validator->getErrors();
                throw new Exception('Invalid data');
            } else {
                $email = $this->request->getPost('email');
                $user = $this->usermodel->where('email', $email)->first();

                $uuid = Uuid::uuid4();
                $key = getenv('jwt.secret', 'HS256');
                $iat = time();
                $exp = time() + (int) env('jwt.ttl', 3600);

                $session = $uuid->toString();

                $payload = [
                    "iat" => $iat, //Time the JWT issued at
                    "exp" => $exp, // Expiration time of token
                    "userdata" => [
                        'id' => $user->id,
                        'session' => $session
                    ]
                ];
                $accessToken = JWT::encode($payload, $key, 'HS256');

                $data = [
                    'message' => 'Login Success',
                    'access_token' => $accessToken,
                    'refresh_token' => $this->generateRefreshToken($user->id)
                ];

                return $this->respond($data);
            }
        } catch (Exception $e) {
            return $this->fail($this->errors ?? $e->getMessage());
        }
    }
    private function generateRefreshToken($user_id)
    {
        $refreshToken = bin2hex(random_bytes(32));

        $RefreshTokens = new RefreshTokens();

        $RefreshTokens->set([
            'token' => $refreshToken, 'user_id' => $user_id
        ])->insert();
        return $refreshToken;
    }

    public function refresh()
    {
        try {
            $rules = [
                'refresh_token'    => 'required|hex|is_not_unique[refresh_tokens.token]',
            ];
            $error = [
                'refresh_token' => ['hex' => "Require valid token", 'is_not_unique' => 'Refresh token not found. Please try to login. ']
            ];
            if (!$this->validate($rules, $error)) {
                $this->errors = $this->validator->getErrors();
                throw new Exception('Invalid data');
            } else {
                $refresh_token = $this->request->getPost('refresh_token');
                $RefreshTokens = new RefreshTokens();

                $tokendata = $RefreshTokens->select('id,user_id')->where('token', $refresh_token)->first();
                $RefreshTokens->delete($tokendata->id);

                $uuid = Uuid::uuid4();
                $key = getenv('jwt.secret', 'HS256');
                $iat = time();
                $exp = time() + (int) env('jwt.ttl', 3600);

                $session = $uuid->toString();

                $payload = [
                    "iat" => $iat, //Time the JWT issued at
                    "exp" => $exp, // Expiration time of token
                    "userdata" => [
                        'id' => $tokendata->user_id,
                        'session' => $session
                    ]
                ];
                $accessToken = JWT::encode($payload, $key, 'HS256');

                $data = [
                    'message' => 'Renewed Access Token Success',
                    'access_token' => $accessToken,
                    'refresh_token' => $this->generateRefreshToken($tokendata->user_id)
                ];

                return $this->respond($data);
            }
        } catch (Exception $e) {
            return $this->fail($this->errors ?? $e->getMessage());
        }
    }

    public function userdata()
    {

        try {


            // return $this->failUnauthorized('Invalid Auth token');
            $users = $this->usermodel->get()->getResult();



            $data = [
                'status' => 200,
                'data' => $this->session->userdata ?? []
            ];



            return $this->respond($data);
        } catch (Exception $e) {



            return $this->fail($this->errors ?? $e->getMessage());
        }
    }
}
