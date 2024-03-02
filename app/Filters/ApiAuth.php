<?php

namespace App\Filters;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use App\Models\UserModel;


class ApiAuth implements FilterInterface
{

    /**
     * Do whatever processing this filter needs to do.
     * By default it should not return anything during
     * normal execution. However, when an abnormal state
     * is found, it should return an instance of
     * CodeIgniter\HTTP\Response. If it does, script
     * execution will end and that Response will be
     * sent back to the client, allowing for error pages,
     * redirects, etc.
     *
     * @param RequestInterface $request
     * @param array|null       $arguments
     *
     * @return RequestInterface|ResponseInterface|string|void
     */
    public function before(RequestInterface $request, $arguments = null)
    {

        try {
            $authHeader = $request->getHeaderLine('Authorization');

            if (empty($authHeader)) {
                throw new \Exception("Authorization header is missing", 401);
            }

            $token = $this->extractToken($authHeader);
            if (!$token) {
                throw new \Exception('Token not found', 401);
            }

            try {
                $key = env('jwt.secret');
                $algorithm = env('jwt.algorithm', 'HS256');
                $JwtPayload = JWT::decode($token, new Key($key, $algorithm));
            } catch (\Throwable $e) {
                throw new \Exception($e->getMessage(), 401);
            }

            $user_id = $JwtPayload->userdata->id ?? false;
            if (!$user_id) {
                throw new \Exception("User data not found");
            }

            $UserModel = new UserModel();

            $user = $UserModel->where('id', $user_id)->first();

            if (!$user) {
                throw new \Exception("User not Found", 401);
            }

            if ($user->is_ban == 1) {
                throw new \Exception("The has been banned", 401);
            }

            session()->set('userdata', $user);
            
            return $request;
        } catch (\Throwable $th) {
            $payload = [
                'status' => $th->getCode(),
                'error' => $th->getCode(),
                'messages' => [
                    "error" => $th->getMessage()
                ]

            ];
            $response = \Config\Services::response();
            $response->setJson($payload);
            $response->setStatusCode($th->getCode());
            return $response;
        }
    }

    /**
     * Allows After filters to inspect and modify the response
     * object as needed. This method does not allow any way
     * to stop execution of other after filters, short of
     * throwing an Exception or Error.
     *
     * @param RequestInterface  $request
     * @param ResponseInterface $response
     * @param array|null        $arguments
     *
     * @return ResponseInterface|void
     */
    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        //
        session()->destroy();
    }

    private function extractToken($header)
    {
        if (preg_match('/Bearer\s(\S+)/', $header, $matches)) {
            return $matches[1];
        }
        return null;
    }
}
