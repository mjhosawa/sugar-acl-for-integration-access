<?php

class SugarACLIntegrationAccess extends SugarACLStrategy
{
    protected bool $isAccess;

    protected $deniedActions = [
        'edit' => 0,
        'import' => 0,
        'create' => 0,
        'massupdate' => 0,
    ];

    public function __construct()
    {
        // Check here if user has access to integration system
        // eg. $client = IntegrationSytem::getClient()
        // $this->isAccess = $client ?? false;
        $this->isAccess = true;
    }

    protected function _canUserWrite(array $context)
    {
        return !$this->isAccess;
    }

    public function checkAccess(string $module, string $view, array $context)
    {
        $view = SugarACLStrategy::fixUpActionName($view);

        if (!in_array($view, $this->deniedActions) || !isset($context['bean'])) {
            return true;
        }

        if ($this->_canUserWrite($context)) {
            return true;
        }

        return false;
    }

    public function getUserAccess(string $module, array $accessList = [], array $context = [])
    {
        $acl = parent::getUserAccess($module, $accessList, $context);

        if (!$this->_canUserWrite($context)) {
            $acl = array_replace($acl, $this->deniedActions);
        }

        return $acl;
    }
}
