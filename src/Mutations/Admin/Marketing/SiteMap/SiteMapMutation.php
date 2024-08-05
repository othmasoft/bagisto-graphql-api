<?php

namespace Webkul\GraphQLAPI\Mutations\Admin\Marketing\SiteMap;

use Nuwave\Lighthouse\Support\Contracts\GraphQLContext;
use Webkul\Admin\Http\Controllers\Controller;
use Webkul\GraphQLAPI\Validators\CustomException;
use Webkul\Sitemap\Repositories\SitemapRepository;

class SiteMapMutation extends Controller
{
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct(protected SitemapRepository $sitemapRepository) {}

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

        bagisto_graphql()->validate($params, [
            'file_name' => 'required',
            'path'      => 'required',
        ]);

        try {
            $sitemap = $this->sitemapRepository->create($params);

            return $sitemap;
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

        bagisto_graphql()->validate($params, [
            'file_name' => 'required',
            'path'      => 'required',
        ]);

        try {
            $sitemap = $this->sitemapRepository->update($params, $id);
            $sitemap = $this->sitemapRepository->find($id);

            return $sitemap;
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

        $sitemap = $this->sitemapRepository->find($id);

        try {
            if ($sitemap) {
                $sitemap->delete();

                return [
                    'status'  => true,
                    'message' => trans('bagisto_graphql::app.admin.marketing.sitemaps.delete-success'),
                ];
            }

            return [
                'status'  => false,
                'message' => trans('bagisto_graphql::app.admin.marketing.sitemaps.delete-failed'),
            ];
        } catch (\Exception $e) {
            throw new CustomException($e->getMessage());
        }
    }
}
