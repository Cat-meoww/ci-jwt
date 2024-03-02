<?php

namespace App\Validation;

use App\Models\UserModel;

class UserRules
{
    public function validate_user(string $str, string $fields, array $data, &$error)
    {
        $model = new UserModel();
        $user = $model->where('email', $data['email'])->first();


        if (!$user) {
            $error = "Email doesn't match";
            return false;
        }

        if ($user->is_ban == 1) {
            $error = "User has be temporarily banned";
            return false;
        }

        if (md5($data['password']) != $user->password) {
            $error = "Password doesn't match";
            return false;
        } else {
            return true;
        }
    }
}
