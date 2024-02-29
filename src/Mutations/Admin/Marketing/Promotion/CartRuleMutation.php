<?php

namespace Webkul\GraphQLAPI\Mutations\Admin\Marketing\Promotion;

use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Event;
use Nuwave\Lighthouse\Support\Contracts\GraphQLContext;
use Exception;
use Webkul\Admin\Http\Controllers\Controller;
use Webkul\CartRule\Repositories\CartRuleRepository;
use Webkul\CartRule\Repositories\CartRuleCouponRepository;
use Webkul\GraphQLAPI\Validators\Admin\CustomException;

class CartRuleMutation extends Controller
{
    /**
     * Create a new controller instance.
     *
     * @param \Webkul\CartRule\Repositories\CartRuleRepository  $cartRuleRepository
     * @param \Webkul\CartRule\Repositories\CartRuleCouponRepository  $cartRuleCouponRepository
     * @return void
     */
    public function __construct(
        protected CartRuleRepository $cartRuleRepository,
        protected CartRuleCouponRepository $cartRuleCouponRepository
    ) {
    }

    /**
     * Store a newly created resource in storage.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function store($rootValue, array $args, GraphQLContext $context)
    {
        if (empty($args['input'])) {
            throw new CustomException(trans('bagisto_graphql::app.admin.response.error.invalid-parameter'));
        }

        $params = $args['input'];

        $params['use_auto_generation'] = empty($params['use_auto_generation']) ? 0 : 1;

        $validator = Validator::make($params, [
            'name'                => 'required',
            'channels'            => 'required|array|min:1',
            'customer_groups'     => 'required|array|min:1',
            'coupon_type'         => 'required',
            'use_auto_generation' => 'required_if:coupon_type,==,1',
            'coupon_code'         => 'required_if:use_auto_generation,==,0',
            'starts_from'         => 'nullable|date',
            'ends_till'           => 'nullable|date|after_or_equal:starts_from',
            'action_type'         => 'required',
            'discount_amount'     => 'required|numeric',
        ]);

        if ($validator->fails()) {
            throw new CustomException($validator->messages());
        }

        try {
            Event::dispatch('promotions.cart_rule.create.before');

            $cartRule = $this->cartRuleRepository->create($params);

            Event::dispatch('promotions.cart_rule.create.after', $cartRule);

            return $cartRule;
        } catch (\Exception $e) {
            throw new CustomException($e->getMessage());
        }
    }

    /**
     * Update the specified resource in storage.
     *
     * @return \Illuminate\Http\Response
     */
    public function update($rootValue, array $args, GraphQLContext $context)
    {
        if (
            empty($args['id'])
            || empty($args['input'])
        ) {
            throw new CustomException(trans('bagisto_graphql::app.admin.response.error.invalid-parameter'));
        }

        $params = $args['input'];
        $id = $args['id'];

        $params['use_auto_generation'] = empty($params['use_auto_generation']) ? 0 : empty($params['use_auto_generation']);

        $validator = Validator::make($params, [
            'name'                => 'required',
            'channels'            => 'required|array|min:1',
            'customer_groups'     => 'required|array|min:1',
            'coupon_type'         => 'required',
            'use_auto_generation' => 'required_if:coupon_type,==,1',
            'coupon_code'         => 'required_if:use_auto_generation,==,0',
            'starts_from'         => 'nullable|date',
            'ends_till'           => 'nullable|date|after_or_equal:starts_from',
            'action_type'         => 'required',
            'discount_amount'     => 'required|numeric',
        ]);

        if ($validator->fails()) {
            throw new CustomException($validator->messages());
        }

        try {
            $cartRule = $this->cartRuleRepository->findOrFail($id);

            Event::dispatch('promotions.cart_rule.update.before', $cartRule);

            if (isset($params['autogenerated_coupons'])) {
                $this->generateCoupons($params['autogenerated_coupons'], $id);

                unset($params['autogenerated_coupons']);
            }

            $cartRule = $this->cartRuleRepository->update($params, $id);

            Event::dispatch('promotions.cart_rule.update.after', $cartRule);

            return $cartRule;
        } catch (\Exception $e) {
            throw new CustomException($e->getMessage());
        }
    }

    /**
     * Remove the specified resource from storage.
     *
     * @return \Illuminate\Http\Response
     */
    public function delete($rootValue, array $args, GraphQLContext $context)
    {
        if (empty($args['id'])) {
            throw new CustomException(trans('bagisto_graphql::app.admin.response.error.invalid-parameter'));
        }

        $id = $args['id'];

        $cartRule = $this->cartRuleRepository->find($id);

        try {
            if ($cartRule) {
                Event::dispatch('promotions.cart_rule.delete.before', $id);

                $cartRule->delete();

                Event::dispatch('promotions.cart_rule.delete.after', $id);

                return ['success' => trans('bagisto_graphql::app.admin.marketing.promotions.cart-rules.delete-success')];
            }

            throw new CustomException(trans('bagisto_graphql::app.admin.marketing.promotions.cart-rules.delete-failed'));
        } catch (Exception $e) {
            throw new CustomException($e->getMessage());
        }
    }

    /**
     * Generate coupon code for cart rule
     *
     * @return Response
     */
    public function generateCoupons($params, $id)
    {
        Validator::make($params, [
            'coupon_qty'  => 'required|integer|min:1',
            'code_length' => 'required|integer|min:10',
            'code_format' => 'required',
        ]);

        try {
            if (! $id) {
                throw new CustomException(trans('bagisto_graphql::app.admin.marketing.promotions.cart-rules.cart-rule-not-defind'));
            }

            $coupon = $this->cartRuleCouponRepository->generateCoupons($params, $id);

            return $coupon;
        } catch (Exception $e) {
            throw new CustomException($e->getMessage());
        }
    }
}
