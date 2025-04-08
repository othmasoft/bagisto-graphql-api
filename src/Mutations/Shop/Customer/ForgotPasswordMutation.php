<?php

namespace Webkul\GraphQLAPI\Mutations\Shop\Customer;

use App\Http\Controllers\Controller;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Foundation\Auth\SendsPasswordResetEmails;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Nuwave\Lighthouse\Support\Contracts\GraphQLContext;
use Symfony\Component\Mailer\Exception\TransportException;
use Webkul\GraphQLAPI\Validators\CustomException;

class ForgotPasswordMutation extends Controller
{
    use SendsPasswordResetEmails;

    /**
     * Method to reset the customer password
     *
     * @return array
     *
     * @throws CustomException
     */
    public function forgot(mixed $rootValue, array $args, GraphQLContext $context)
    {
        bagisto_graphql()->validate($args, [
            'email' => 'required|email|exists:customers,email',
        ]);

        try {
            $response = $this->broker()->sendResetLink($args);

            if ($response == Password::RESET_LINK_SENT) {
                return [
                    'success' => true,
                    'message' => trans('bagisto_graphql::app.shop.customers.forgot-password.reset-link-sent'),
                ];
            }

            if ($response == Password::RESET_THROTTLED) {
                return [
                    'success' => true,
                    'message' => trans('bagisto_graphql::app.shop.customers.forgot-password.already-sent'),
                ];
            }

            throw new CustomException(trans('bagisto_graphql::app.shop.customers.forgot-password.email-not-exist'));
        } catch (TransportException $e) {
            DB::table('customer_password_resets')->where('email', $args['email'])->delete();

            throw new CustomException(trans('bagisto_graphql::app.email.configuration-error'));
        } catch (\Exception $e) {
            report($e);

            throw new CustomException($e->getMessage());
        }
    }


    public function reset(mixed $rootValue, array $args, GraphQLContext $context)
    {
        try {
            bagisto_graphql()->validate($args, [
                'token'    => 'required',
                'email' => 'required|email|exists:customers,email',
                'password' => 'required|confirmed|min:6',

            ]);

            $response = $this->broker()->reset(
                request(['email', 'password', 'password_confirmation', 'token']), function ($customer, $password) {
                $this->resetPassword($customer, $password);
            }
            );

            if ($response == Password::PASSWORD_RESET) {
                $customer = $this->customerRepository->findOneByField('email', request('email'));

                Event::dispatch('customer.password.update.after', $customer);

                return [
                    'success' => true,
                    'message' => trans('bagisto_graphql::app.shop.customers.forgot-password.success'),
                ];
            }

            if ($response == Password::INVALID_USER) {
                return [
                    'success' => false,
                    'message' => trans('bagisto_graphql::app.shop.customers.forgot-password.invalid_user'),
                ];
            }

            return [
                'success' => false,
                'message' => trans('bagisto_graphql::app.shop.customers.forgot-password.fail'),
            ];

        } catch (\Exception $e) {

            return [
                'success' => false,
                'message' => trans('bagisto_graphql::app.shop.customers.forgot-password.error').$e->getMessage(),
            ];
        }
    }

    protected function resetPassword($customer, $password)
    {
        $customer->password = Hash::make($password);

        $customer->setRememberToken(Str::random(60));

        $customer->save();

    }


    /**
     * Get the broker to be used during password reset.
     *
     * @return \Illuminate\Contracts\Auth\PasswordBroker
     */
    public function broker()
    {
        return Password::broker('customers');
    }
}
