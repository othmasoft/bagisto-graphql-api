<?php

namespace Webkul\GraphQLAPI\Mutations\Shop\Customer;

use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Nuwave\Lighthouse\Support\Contracts\GraphQLContext;
use Webkul\CartRule\Repositories\CartRuleCouponRepository;
use Webkul\Checkout\Facades\Cart;
use Webkul\Core\Rules\PhoneNumber;
use Webkul\Customer\Repositories\CustomerAddressRepository;
use Webkul\GraphQLAPI\Repositories\NotificationRepository;
use Webkul\GraphQLAPI\Validators\CustomException;
use Webkul\Payment\Facades\Payment;
use Webkul\Rewards\Repositories\RewardPointRepository;
use Webkul\Sales\Repositories\OrderRepository;
use Webkul\Sales\Transformers\OrderResource;
use Webkul\Shipping\Facades\Shipping;
use Webkul\Rewards\Helpers\CartHelper;


class CheckoutMutation extends Controller
{
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct(
        protected CartRuleCouponRepository $cartRuleCouponRepository,
        protected CustomerAddressRepository $customerAddressRepository,
        protected OrderRepository $orderRepository,
        protected NotificationRepository $notificationRepository,
        protected CartHelper $cartHelper,
        protected RewardPointRepository $rewardPointRepository,


    ) {
        Auth::setDefaultDriver('api');
    }

    /**
     * Returns a customer's addresses detail.
     *
     * @return array
     *
     * @throws CustomException
     */
    public function addresses(mixed $rootValue, array $args, GraphQLContext $context)
    {
        try {
            $customer = bagisto_graphql()->authorize();

            $formattedAddresses = [];

            foreach ($customer->addresses as $key => $address) {
                $formattedAddresses[$key] = [
                    'id'      => $address->id,
                    'address' => "{$customer->first_name} {$customer->last_name}, {$address->address}, {$address->city}, {$address->state}, {$address->country}, {$address->postcode},{$address->dial_code}, T: {$address->phone}",
                ];
            }

            return [
                'is_guest'        => empty($customer),
                'customer'        => $customer,
                'addresses'       => $formattedAddresses,
                'default_country' => config('app.default_country') ?? 'IN',
            ];
        } catch (\Exception $e) {
            throw new CustomException($e->getMessage());
        }
    }

    /**
     * Store a newly created resource in storage and return shipping methods.
     *
     * @return array
     *
     * @throws CustomException
     */
    public function saveCartAddresses(mixed $rootValue, array $args, GraphQLContext $context)
    {
        $rules = [];

        $rules = array_merge($rules, $this->mergeAddressRules('billing'));

        if (
            empty($args['billing']['use_for_shipping'])
            && Cart::getCart()->haveStockableItems()
        ) {
            $rules = array_merge($rules, $this->mergeAddressRules('shipping'));
        }

        bagisto_graphql()->validate($args, $rules);

        if (Cart::getCart() &&
            ! auth()->guard('api')->check()
            && ! Cart::getCart()->hasGuestCheckoutItems()
        ) {
            throw new CustomException(trans('bagisto_graphql::app.shop.checkout.addresses.guest-address-warning'));
        }

        if (Cart::hasError()) {
            throw new CustomException(current(Cart::getErrors()));
        }

        if (auth()->guard('api')->check()) {
            $args = array_merge($args, [
                'billing' => array_merge($args['billing'], [
                    'customer_id' => auth()->guard('api')->user()->id,
                ]),
            ]);

            if (
                empty($args['billing']['use_for_shipping'])
                && Cart::getCart()->haveStockableItems()
            ) {
                $args = array_merge($args, [
                    'shipping' => array_merge($args['shipping'], [
                        'customer_id' => auth()->guard('api')->user()->id,
                    ]),
                ]);
            }

            if (! empty($args['billing']['save_address'])) {
                $this->customerAddressRepository->create(array_merge($args['billing'], [
                    'address' => implode(PHP_EOL, $args['billing']['address']),
                ]));
            }
        }

        Cart::saveAddresses($args);

        $cart = Cart::getCart();

        Cart::collectTotals();

        if ($cart->haveStockableItems()) {
            if (! $rates = Shipping::collectRates()) {
                throw new CustomException(trans('bagisto_graphql::app.shop.checkout.something-wrong'));
            }

            $shipping_methods = [];

            foreach ($rates['shippingMethods'] as $shippingMethod) {
                $methods = [];

                foreach ($shippingMethod['rates'] as $rate) {
                    $methods = [
                        'code'                 => $rate->method,
                        'label'                => $rate->method_title,
                        'price'                => $rate->price,
                        'formatted_price'      => core()->formatPrice($rate->price),
                        'base_price'           => $rate->base_price,
                        'formatted_base_price' => core()->formatBasePrice($rate->base_price),
                    ];
                }

                $shipping_methods[] = [
                    'title'   => $shippingMethod['carrier_title'],
                    'methods' => $methods,
                ];
            }

            return [
                'message'          => trans('bagisto_graphql::app.shop.checkout.addresses.address-save-success'),
                'cart'             => Cart::getCart(),
                'shipping_methods' => $shipping_methods,
                'payment_methods' => Payment::getPaymentMethods(),
                'jump_to_section'  => 'shipping',
            ];
        }

        return [
            'message'         => trans('bagisto_graphql::app.shop.checkout.addresses.address-save-success'),
            'cart'            => Cart::getCart(),
            'payment_methods' => Payment::getPaymentMethods(),
            'jump_to_section' => 'payment',
        ];
    }

    /**
     * Merge new address rules.
     */
    private function mergeAddressRules(string $addressType): array
    {
        return [
            "{$addressType}.company_name" => ['nullable'],
            "{$addressType}.first_name"   => ['required'],
            "{$addressType}.last_name"    => ['required'],
            "{$addressType}.email"        => ['required'],
            "{$addressType}.address"      => ['required', 'array', 'min:1'],
            "{$addressType}.city"         => ['required'],
            "{$addressType}.country"      => ['required'],
            "{$addressType}.state"        => ['required'],
            "{$addressType}.postcode"     => ['required', 'numeric'],
            "{$addressType}.dial_code"    => ['required'],
            "{$addressType}.phone"        => ['required', new PhoneNumber],
        ];
    }

    /**
     * get shipping methods based on the cart address.
     *
     * @return array
     *
     * @throws CustomException
     */
    public function shippingMethods(mixed $rootValue, array $args, GraphQLContext $context)
    {
        $cart = Cart::getCart();


        if (! $cart) {
            throw new CustomException(trans('bagisto_graphql::app.shop.checkout.empty-cart'));
        }

        if (Cart::getCart() &&
            ! auth()->guard('api')->check()
            && ! Cart::getCart()->hasGuestCheckoutItems()
        ) {
            throw new CustomException(trans('bagisto_graphql::app.shop.checkout.invalid-guest-user'));
        }

        if (empty($cart->shipping_address->id)) {
            throw new CustomException(trans('bagisto_graphql::app.shop.checkout.no-address-found'));
        }

        Cart::collectTotals();

        if ($cart->haveStockableItems()) {
            if (! $rates = Shipping::collectRates()) {
                throw new CustomException(trans('bagisto_graphql::app.shop.checkout.shipping.method-not-found'));
            }

            $shipping_methods = [];

            foreach ($rates['shippingMethods'] as $shippingMethod) {
                $methods = [];

                foreach ($shippingMethod['rates'] as $rate) {
                    $methods = [
                        'code'                 => $rate->method,
                        'label'                => $rate->method_title,
                        'price'                => $rate->price,
                        'formatted_price'      => core()->formatPrice($rate->price),
                        'base_price'           => $rate->base_price,
                        'formatted_base_price' => core()->formatBasePrice($rate->base_price),
                    ];
                }

                $shipping_methods[] = [
                    'title'   => $shippingMethod['carrier_title'],
                    'methods' => $methods,
                ];
            }

            return [
                'message'          => trans('bagisto_graphql::app.shop.checkout.shipping.method-fetched'),
                'cart'             => Cart::getCart(),
                'shipping_methods' => $shipping_methods,
                'jump_to_section'  => 'shipping',
            ];
        } else {
            return [
                'message'         => trans('bagisto_graphql::app.shop.checkout.payment.method-fetched'),
                'cart'            => Cart::getCart(),
                'payment_methods' => Payment::getPaymentMethods(),
                'jump_to_section' => 'payment',
            ];
        }
    }

    /**
     * Save Payment Method
     *
     * @return array
     *
     * @throws CustomException
     */
    public function saveShipping(mixed $rootValue, array $args, GraphQLContext $context)
    {
        bagisto_graphql()->validate($args, [
            'method' => 'required',
        ]);

        try {
            if (
                Cart::hasError()
                || ! Cart::saveShippingMethod($args['method'])
            ) {
                throw new CustomException(trans('bagisto_graphql::app.shop.checkout.shipping.save-failed'));
            }

            Cart::collectTotals();

            return [
                'message'         => trans('bagisto_graphql::app.shop.checkout.shipping.save-success'),
                'cart'            => Cart::getCart(),
                'jump_to_section' => 'payment',
            ];
        } catch (\Exception $e) {
            throw new CustomException($e->getMessage());
        }
    }

    /**
     * get the available payment methods and save the shipping for the current cart.
     *
     * @return array
     *
     * @throws CustomException
     */
    public function paymentMethods(mixed $rootValue, array $args, GraphQLContext $context)
    {
        bagisto_graphql()->validate($args, [
            'shipping_method' => 'string|required',
        ]);

        try {
            if (
                Cart::hasError()
                || ! Cart::saveShippingMethod($args['shipping_method'])
            ) {
                throw new CustomException(trans('bagisto_graphql::app.shop.checkout.payment.method-not-found'));
            }

            Cart::collectTotals();

            return [
                'message'         => trans('bagisto_graphql::app.shop.checkout.payment.method-fetched'),
                'cart'            => Cart::getCart(),
                'payment_methods' => Payment::getPaymentMethods(),
                'jump_to_section' => 'payment',
            ];
        } catch (\Exception $e) {
            throw new CustomException($e->getMessage());
        }
    }

    /**
     * Save Payment Method
     *
     * @return array
     *
     * @throws CustomException
     */
    public function savePayment(mixed $rootValue, array $args, GraphQLContext $context)
    {
        bagisto_graphql()->validate($args, [
            'method' => 'required|in:'.implode(',', collect(Payment::getPaymentMethods())->pluck('method')->toArray()),
        ]);

        try {
            if (
                Cart::hasError()
                || ! Cart::savePaymentMethod($args)
            ) {
                throw new CustomException(trans('bagisto_graphql::app.shop.checkout.payment.save-failed'));
            }

            Cart::collectTotals();

            return [
                'message'         => trans('bagisto_graphql::app.shop.checkout.payment.save-success'),
                'cart'            => Cart::getCart(),
                'jump_to_section' => 'review',
            ];
        } catch (\Exception $e) {
            throw new CustomException($e->getMessage());
        }
    }

    /**
     * Apply Coupon to cart
     *
     * @return array
     *
     * @throws CustomException
     */
    public function applyCoupon(mixed $rootValue, array $args, GraphQLContext $context)
    {
        bagisto_graphql()->validate($args, [
            'code' => 'string|required',
        ]);

        try {
            if (strlen($args['code'])) {
                $coupon = $this->cartRuleCouponRepository->findOneByField('code', $args['code']);

                if (! $coupon) {
                    return [
                        'success' => false,
                        'message' => trans('bagisto_graphql::app.shop.checkout.coupon.invalid-code'),
                        'cart'    => Cart::getCart(),
                    ];
                }

                if ($coupon->cart_rule->status) {
                    if (Cart::getCart()->coupon_code == $args['code']) {
                        return [
                            'success' => true,
                            'message' => trans('bagisto_graphql::app.shop.checkout.coupon.already-applied'),
                            'cart'    => Cart::getCart(),
                        ];
                    }

                    Cart::setCouponCode($args['code'])->collectTotals();

                    if (Cart::getCart()->coupon_code == $args['code']) {
                        return [
                            'success' => true,
                            'message' => trans('bagisto_graphql::app.shop.checkout.coupon.apply-success'),
                            'cart'    => Cart::getCart(),
                        ];
                    }
                }
            }

            return [
                'success' => false,
                'message' => trans('bagisto_graphql::app.shop.checkout.coupon.invalid-code'),
                'cart'    => Cart::getCart(),
            ];
        } catch (\Exception $e) {
            throw new CustomException($e->getMessage());
        }
    }

    /**
     * Remove Coupon from cart
     *
     * @return array
     *
     * @throws CustomException
     */
    public function removeCoupon(mixed $rootValue, array $args, GraphQLContext $context)
    {
        try {
            if (Cart::getCart()->coupon_code) {
                Cart::removeCouponCode()->collectTotals();

                return [
                    'success' => true,
                    'message' => trans('bagisto_graphql::app.shop.checkout.coupon.remove-success'),
                    'cart'    => Cart::getCart(),
                ];
            }

            return [
                'success' => false,
                'message' => trans('bagisto_graphql::app.shop.checkout.couponremove-failed'),
                'cart'    => Cart::getCart(),
            ];
        } catch (\Exception $e) {
            throw new CustomException($e->getMessage());
        }
    }



    /**
     * Apply Coupon to cart
     *
     * @return array
     *
     * @throws CustomException
     */
    public function applyPoints(mixed $rootValue, array $args, GraphQLContext $context)
    {
        bagisto_graphql()->validate($args, [
            'points' => 'int|required',
        ]);

        $cart = Cart::getCart();

        if (!$cart) {
            return [
                'success' => false,
                'message' => 'Cart not found.',
                'cart'    => null, // Ensure this field is nullable in GraphQL schema
            ];
        }

        $totalRewardPoints = $this->rewardPointRepository->totalRewardPoints(auth()->guard('api')->user()->id);

        $maxRewardPoints = core()->getConfigData('reward.general.general.reward-used-at-one-time') ?? 999;

        try {
            if (strlen($args['points'])) {
                $points = $args['points'];
                if ($cart->points) {
                    Cart::removePoints()->collectTotals();
                }

                $redemption = $this->cartHelper->redemption($points);

                if ($redemption > $cart->base_grand_total) {
                    return [
                        'success' => false,
                        'message' => trans('rewards::app.checkout.total.warning-required-less-point'),
                        'cart'    => Cart::getCart(),
                    ];
                }

                if ($totalRewardPoints < $points) {
                    return [
                        'success' => false,
                        'message' => trans('rewards::app.checkout.total.you-have-only').$totalRewardPoints.' Points',
                        'cart'    => Cart::getCart(),
                    ];
                }

                if ($maxRewardPoints < $points) {
                    return [
                        'success' => false,
                        'message' => trans('rewards::app.checkout.total.use-can-use-only').$maxRewardPoints.' points at a time',
                        'cart'    => Cart::getCart(),
                    ];
                }

                Cart::setPoints($points)->collectTotals();

                if (Cart::getCart()->points == $points) {
                    return [
                        'success' => true,
                        'message' => trans('rewards::app.checkout.total.success-points'),
                        'cart'    => Cart::getCart(),
                    ];
                }
            }

            return [
                'success' => false,
                'message' => trans('bagisto_graphql::app.shop.checkout.coupon.invalid-code'),
                'cart'    => Cart::getCart(),
            ];
        } catch (\Exception $e) {
            throw new CustomException($e->getMessage());
        }
    }


    /**
     * Apply coupon to the cart
     *
     * @return \Illuminate\Http\Response
     */
    public function removePoints()
    {
        try {
            Cart::removePoints()->collectTotals();

            return [
                'success' => true,
                'message' => trans('bagisto_graphql::app.shop.checkout.reward.remove-success'),
                'cart'    => Cart::getCart(),
            ];

        } catch (\Exception $e) {
            throw new CustomException($e->getMessage());
        }
    }

    /**
     * Save Order
     *
     * @return array
     *
     * @throws CustomException
     */
    public function saveOrder(mixed $rootValue, array $args, GraphQLContext $context)
    {
        try {
            if (Cart::hasError()) {
                throw new CustomException(trans('bagisto_graphql::app.shop.checkout.error-placing-order'));
            }

            Cart::collectTotals();

            $this->validateOrder();

            $cart = Cart::getCart();

            if ($redirectUrl = Payment::getRedirectUrl($cart)) {
                return [
                    'success'         => true,
                    'redirect_url'    => $redirectUrl,
                    'selected_method' => $cart->payment->method,
                ];
            }

            $data = (new OrderResource($cart))->jsonSerialize();
            $data['points'] = $cart->points;
            $data['points_amount'] = $cart->points_amount;

            $order = $this->orderRepository->create($data);
            $this->rewardPointRepository->create($order);

            if (core()->getConfigData('general.api.pushnotification.private_key')) {
                $this->prepareNotificationContent($order);
            }

            Cart::deActivateCart();

            return [
                'success'      => true,
                'redirect_url' => null,
                'order'        => $order,
            ];
        } catch (\Exception $e) {
            throw new CustomException($e->getMessage());
        }
    }

    /**
     * Validate order before creation
     *
     * @return void|CustomException
     */
    public function validateOrder()
    {
        $cart = Cart::getCart();

        if (
            $cart->haveStockableItems()
            && ! $cart->shipping_address
        ) {
            throw new CustomException(trans('bagisto_graphql::app.shop.checkout.missing-shipping-address'));
        }

        if (! $cart->billing_address) {
            throw new CustomException(trans('bagisto_graphql::app.shop.checkout.missing-billing-address'));
        }

        if (
            $cart->haveStockableItems()
            && ! $cart->selected_shipping_rate
        ) {
            throw new CustomException(trans('bagisto_graphql::app.shop.checkout.missing-shipping-method'));
        }

        if (! $cart->payment) {
            throw new CustomException(trans('bagisto_graphql::app.shop.checkout.missing-payment-method'));
        }
    }

    /**
     * Prepare data for order push notification.
     *
     * @param  \Webkul\Sales\Contracts\Order  $order
     * @return mixed
     */
    public function prepareNotificationContent($order)
    {
        $data = [
            'title'       => 'New Order Placed',
            'body'        => 'Order ('.$order->id.') placed by '.$order->customerFullName.' successfully.',
            'message'     => 'Order ('.$order->id.') placed by '.$order->customerFullName.' successfully.',
            'sound'       => 'default',
            'orderStatus' => $order->parcel_status,
            'orderId'     => (string) $order->id,
            'type'        => 'order',
        ];

        $notification = [
            'title'   => $data['title'],
            'content' => $data['body'],
        ];

        $this->notificationRepository->sendNotification($data, $notification);
    }
}
